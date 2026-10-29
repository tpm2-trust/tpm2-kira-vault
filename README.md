# tpm2-kira-vault

The vault of [tpm2-kira](../tpm2-kira)'s `tpm+vault` keyslots. Such a keyslot
opens with a key made from two parts: one stays in the machine's TPM, the
other is kept here, wrapped so that only that machine's TPM opens it. At
boot the machine's initrd asks for it, and the vault releases it only to a
fresh TPM quote of a boot state that the machine's own signing key
approved. The records are encrypted under keys sealed to this vault's TPM
and its own PCRs.

**The documentation is tpm2-kira's
[docs/VAULT.md](../tpm2-kira/docs/VAULT.md)**: the design and
threat model, setting up both sides, the protocol, the release rules (§6.1),
keys at rest, the admin interface, the state directory, recovery (§6.5), the
commands (§6.6) and the tests. The contract with tpm2-kira is its Go package
`github.com/mrwiora/tpm2-kira/vaultproto`; this module builds against
`../tpm2-kira` (`replace` in go.mod).

## Build

```
make build              # ./tpm2-kira-vault, no cgo
make test               # unit tests, no TPM
make test-integration   # with swtpm
sudo make install       # /usr/bin and the systemd unit
```

## In short

```
vault#    tpm2-kira-vault init --url https://vault.example:8443 --pcrs 7   # write down the recovery key
vault#    systemctl enable --now tpm2-kira-vault                           # and open TCP 8443
vault#    tpm2-kira-vault token create --name db-03                        # prints the machine's command
machine#  tpm2-kira luks enrol /dev/sda2 --mode tpm+vault --url … --pin … --token …
vault#    tpm2-kira-vault devices | requests | audit
vault#    tpm2-kira-vault device revoke db-03                              # a machine reported stolen
```

The operator interface (off by default) lets operators approve releases
over the network, with the pepper of a device enrolled with one:

```
vault#    tpm2-kira-vault config set operator-listen :8444    # serve stopped; or init --operator-listen :8444
vault#    tpm2-kira-vault operator add alice                  # prints the bearer token once, and a curl example
anywhere$ curl -k --pinnedpubkey sha256//<base64 pin> -H "Authorization: Bearer $TOKEN" https://vault.example:8444/v1/requests
anywhere$ curl -k --pinnedpubkey sha256//<base64 pin> -H "Authorization: Bearer $TOKEN" \
            -d '{"pepper":"…"}' https://vault.example:8444/v1/requests/ID/approve
```

It serves `GET /v1/requests`, `POST /v1/requests/{id}/approve` (body `{}`
or `{"pepper":"…"}`), `POST /v1/requests/{id}/deny`, `GET /v1/devices` and
`GET /v1/devices/{id}`, nothing else. `-k` is right: `--pinnedpubkey` is the
check, against the vault's self-signed key.

`tpm2-kira-vault help` lists every command.
