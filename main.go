// Command tpm2-kira-vault keeps the remote parts of tpm2-kira's tpm+vault
// keyslots and releases each to its machine's TPM at boot, by the rules of
// tpm2-kira's docs/VAULT.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
)

const usage = `tpm2-kira-vault keeps the remote parts of tpm2-kira's tpm+vault keyslots
and releases each to its machine's TPM at boot (tpm2-kira docs/VAULT.md).

Usage:
  tpm2-kira-vault init   [--dir DIR] [--listen :8443] [--url https://HOST:8443] [--pcrs 7] [--tpm /dev/tpmrm0]
                         [--admin-socket PATH] [--operator-listen :8444]
  tpm2-kira-vault config set operator-listen ADDR|""   [--dir DIR]
  tpm2-kira-vault serve  [--dir DIR]
  tpm2-kira-vault token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE]
  tpm2-kira-vault devices
  tpm2-kira-vault device show|revoke|unrevoke|unlock DEVICE
  tpm2-kira-vault device mode DEVICE auto|approve
  tpm2-kira-vault requests
  tpm2-kira-vault request approve|deny ID
  tpm2-kira-vault audit  [--follow]
  tpm2-kira-vault operators
  tpm2-kira-vault operator add|remove NAME
  tpm2-kira-vault reseal [--dir DIR] [--pcrs 7]
  tpm2-kira-vault help

init, config and reseal work on the state directory (default
/var/lib/tpm2-kira-vault) and refuse while serve runs. The other commands talk to the running serve over
its admin socket (default /run/tpm2-kira-vault/admin.sock; --socket PATH, or
the one in DIR's configuration with --dir DIR).

DEVICE is a device ID (hex) or a device's unique name. --pcrs takes the
vault's own PCRs (SHA-256 bank), comma-separated; --pcrs "" seals to the TPM
without a PCR policy.

reseal asks for the vault recovery key shown at init, and seals every device
key to the vault's current PCR values.

The operator interface (off unless operator-listen is set) serves
GET /v1/requests, POST /v1/requests/{id}/approve|deny, GET /v1/devices and
GET /v1/devices/{id} over HTTPS with the vault's certificate, to operators
with a bearer token from 'operator add'. A device enrolled with a pepper is
approved with {"pepper":"..."}.
`

// newSealer is the sealing backend for a TPM path; tests replace it.
var newSealer = func(path string) keys.Sealer { return &keys.TPMSealer{Path: path} }

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "tpm2-kira-vault:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("no command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	case "init":
		return cmdInit(rest, stdout, stderr)
	case "serve":
		return cmdServe(rest, stderr)
	case "reseal":
		return cmdReseal(rest, stdin, stdout, stderr)
	case "config":
		return cmdConfig(rest, stdout, stderr)
	case "token", "devices", "device", "requests", "request", "audit", "operators", "operator":
		return cmdAdmin(cmd, rest, stdout, stderr)
	}
	return fmt.Errorf("unknown command %q (tpm2-kira-vault help)", cmd)
}

// parse parses flags anywhere among the arguments and returns the
// positional ones.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// parsePCRs reads "7" or "0,7,14"; "" is no PCRs.
func parsePCRs(s string) ([]uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []uint8{}, nil
	}
	seen := map[uint8]bool{}
	var out []uint8
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 || n > 23 {
			return nil, fmt.Errorf("PCR %q: a number from 0 to 23", f)
		}
		if !seen[uint8(n)] {
			seen[uint8(n)] = true
			out = append(out, uint8(n))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func formatPCRs(p []uint8) string {
	if len(p) == 0 {
		return "none"
	}
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(int(v))
	}
	return strings.Join(s, ",")
}

const noPCRWarning = "Warning: the vault's selection is empty. The device keys are bound to this TPM only, not to the vault's boot state: a vault booted from another system releases them too."
