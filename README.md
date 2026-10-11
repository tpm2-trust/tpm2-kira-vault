# tpm2-kira-vault

The vault of [tpm2-kira](../tpm2-kira)'s `tpm+vault` keyslots. Such a keyslot
opens with a key made from two parts: L stays in the machine's TPM, and R is
kept here. At boot, the machine's initrd asks the vault for R. The vault
releases R only to a fresh TPM quote of a boot state that the machine's own
signing key approved. It never sees R in the clear: R is wrapped so that only
that machine's TPM opens it, and only under the keyslot's policy.

The design and the protocol are in tpm2-kira's
[docs/VAULT.md](../tpm2-kira/docs/VAULT.md). The contract (REST messages and
the release check) is the Go package `github.com/mrwiora/tpm2-kira/vaultproto`.

## Threat model, in short

- **A stolen machine** keeps L in its TPM. Revoke it here and R is no longer
  released, even in a good boot state. Away from the vault's network it does
  not unlock at all.
- **A tampered boot** gets nothing. The quote's PCR values must be ones the
  machine's signing key approved, at a generation no lower than the highest
  this vault has seen.
- **A copy of the vault's disk or a backup** opens nothing. Each device record
  is encrypted with a per-device key K_dev, and K_dev is sealed in the vault's
  TPM to the vault's own PCRs (default PCR 7).
- **Root on the running vault** gets the wrapped R of every device, which is
  useless without each machine's TPM in an approved state. It can deny
  service.
- **Availability** is the main risk. Every machine has a recovery passphrase
  keyslot for the times the vault does not answer.

See docs/VAULT.md §7 for the full table.

## Build

```
make build              # ./tpm2-kira-vault, no cgo
make test               # unit tests, no TPM
make test-integration   # with swtpm
sudo make install       # /usr/bin and the systemd unit
```

## Setup

On the vault host, as root:

```
tpm2-kira-vault init --url https://vault.example:8443 --pcrs 7
systemctl enable --now tpm2-kira-vault
```

`init` checks that the TPM can seal and unseal, and creates
`/var/lib/tpm2-kira-vault` (0700). It writes the TLS key with a self-signed
ECDSA P-256 certificate valid for 100 years, and the configuration. It prints
the pin (`sha256:…` over the certificate's public key) and the **vault
recovery key**. The recovery key is shown once: write it down and keep it
offline. With `--pcrs ""` the device keys are bound to this TPM only, not to
the vault's boot state; init warns about that.

To enrol a machine:

```
vault#    tpm2-kira-vault token create --name db-03 [--mode approve] [--ttl 1h]
machine#  tpm2-kira vault enrol --url … --pin … --token … --out /run/tpm2-kira/luks.key
```

`token create` prints the token, the URL, the pin and the exact command to run
on the machine. A token works once, for an hour by default. To enrol a machine
the vault knows already (a new TPM, a new slot), create the token with
`--replace DEVICE`.

## Commands

| Command | |
|---|---|
| `init [--dir] [--listen :8443] [--url] [--pcrs 7] [--tpm /dev/tpmrm0] [--admin-socket]` | create the state directory |
| `serve [--dir]` | run the vault (the systemd unit does this) |
| `token create --name NAME [--mode auto\|approve] [--ttl 1h] [--replace DEVICE]` | a one-time enrolment token |
| `devices` | the enrolled machines |
| `device show\|revoke\|unrevoke\|unlock DEVICE` | one machine |
| `device mode DEVICE auto\|approve` | release at once, or after an operator's approval |
| `requests` | releases waiting for approval |
| `request approve\|deny ID` | decide one |
| `audit [--follow]` | the audit log |
| `reseal [--dir] [--pcrs 7]` | seal every device key to the vault's current PCRs (asks for the recovery key) |

DEVICE is a hex device ID or a unique name. The admin commands are clients of
`serve`'s root-only Unix socket `/run/tpm2-kira-vault/admin.sock` (`--socket`,
or `--dir` to use the configured one). Its handlers have the shape of version
2's operator REST interface: `GET /v1/devices`, `GET /v1/requests`,
`POST /v1/requests/{id}/approve`, `POST /v1/requests/{id}/deny`, and so on.
The approve body's `pepper` field is reserved for version 2 and refused now.
`init` and `reseal` work on the state directory directly, and refuse while
`serve` runs.

## Release rules

As docs/VAULT.md §4.1:

- A challenge is valid for 120 s and one request.
- A request in approve mode stays pending for 15 minutes.
- 5 failed verifications in a row lock the device until `device unlock`.
- At most 10 challenges per device per minute.
- The highest verified generation is kept, and a lower one is refused.
- Every enrolment, challenge, verification, release, denial and admin action
  goes to `audit.log`, append-only and synced after each line.

Pending requests live in memory only: after a restart, the machine starts with
a new challenge.

## State directory

```
/var/lib/tpm2-kira-vault/
  config.json         listen address, URL, the vault's PCRs, TPM path, admin socket, recovery public key
  tls/key.pem, cert.pem
  devices/<id>.json   pinned device data, release state, the encrypted wrapped R,
                      sealed K_dev, K_dev encrypted to the recovery key
  tokens/<sha256>.json  unused tokens, stored only as their hash
  audit.log
```

Files are 0600 and written atomically. A device's wrapped R is encrypted with
AES-256-GCM under K_dev, with the device ID as AAD. K_dev is a sealed data
object under the owner hierarchy's storage primary, with PolicyPCR over the
vault's selection. It is unsealed for each release only, then wiped.

## Recovery

**The vault's boot state changed** (a firmware update, a Secure Boot change):
every release is denied with "the vault's own boot state changed: run reseal".
Such a denial does not count against the device. Then:

```
systemctl stop tpm2-kira-vault
tpm2-kira-vault reseal [--pcrs 7]    # type the recovery key
systemctl start tpm2-kira-vault
```

The recovery key is an X25519 private key. The vault keeps only its public
key, and encrypts every K_dev to it at enrolment. `reseal` opens those copies
and seals each K_dev to the current PCR values (and to a new selection, given
`--pcrs`).

**The recovery key is lost and the boot state changed:** the records cannot be
opened. Each machine unlocks with its recovery passphrase and is enrolled
again with a `--replace` token.

**The vault is gone:** machines fall back to cryptsetup's prompt and their
recovery passphrase. Restoring a backup of the state directory needs the same
TPM, or the recovery key followed by `reseal` on the new TPM.

**A machine was reported stolen:** `tpm2-kira-vault device revoke DEVICE`.
