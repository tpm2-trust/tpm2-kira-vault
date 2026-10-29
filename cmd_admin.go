package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mrwiora/tpm2-kira/core/vaultproto"

	"github.com/mrwiora/tpm2-kira-vault/internal/server"
	"github.com/mrwiora/tpm2-kira-vault/internal/state"
)

// adminClient talks to serve over its admin socket.
type adminClient struct {
	socket string
	http   *http.Client
}

func newAdminClient(socket string) *adminClient {
	return &adminClient{socket: socket, http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}
}

func (c *adminClient) send(method, path string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://vault"+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rsp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the vault's admin socket %s does not answer (is tpm2-kira-vault serve running?): %w", c.socket, err)
	}
	if rsp.StatusCode/100 != 2 {
		defer rsp.Body.Close()
		var e vaultproto.ErrorResponse
		b, _ := io.ReadAll(rsp.Body)
		if json.Unmarshal(b, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return nil, fmt.Errorf("%s", e.Error)
	}
	return rsp, nil
}

func (c *adminClient) do(method, path string, in, out any) error {
	rsp, err := c.send(method, path, in)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(rsp.Body).Decode(out)
}

func cmdAdmin(cmd string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "state directory whose configured admin socket to use")
	socket := fs.String("socket", "", "the admin socket (default "+state.DefaultAdminSocket+")")
	name := fs.String("name", "", "token create: the machine's name")
	mode := fs.String("mode", vaultproto.ModeAuto, "token create: auto or approve")
	ttl := fs.Duration("ttl", server.DefaultTokenTTL, "token create: how long the token is valid")
	replace := fs.String("replace", "", "token create: the device the token enrols again")
	follow := fs.Bool("follow", false, "audit: keep printing new lines")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *socket == "" {
		*socket = state.DefaultAdminSocket
		if *dir != "" {
			cfg, err := (state.Dir{Path: *dir}).Config()
			if err != nil {
				return err
			}
			*socket = cfg.AdminSocket
		}
	}
	c := newAdminClient(*socket)
	want := func(n int, form string) error {
		if len(pos) != n {
			return fmt.Errorf("usage: tpm2-kira-vault %s", form)
		}
		return nil
	}
	esc := url.PathEscape

	switch cmd {
	case "token":
		if err := want(1, "token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE]"); err != nil {
			return err
		}
		if pos[0] != "create" {
			return fmt.Errorf("unknown token command %q", pos[0])
		}
		var t server.TokenResponse
		if err := c.do("POST", "/v1/tokens", server.TokenRequest{Name: *name, Mode: *mode, TTLSeconds: int(ttl.Seconds()), Replace: *replace}, &t); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Token for %s (mode %s), valid until %s:\n\n", t.Name, t.Mode, t.Expires.Local().Format(time.DateTime))
		fmt.Fprintf(stdout, "  token:  %s\n  URL:    %s\n  pin:    %s\n\n", t.Token, t.URL, t.Pin)
		fmt.Fprintf(stdout, "On the machine, as root:\n\n  %s\n", t.Command)
		return nil

	case "devices":
		if err := want(0, "devices"); err != nil {
			return err
		}
		var list []server.DeviceView
		if err := c.do("GET", "/v1/devices", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DEVICE\tNAME\tMODE\tPEPPER\tSTATE\tGENERATION\tLAST RELEASE")
		for _, d := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", d.ID, d.Name, d.Mode, yesNo(d.Pepper), deviceState(&d), d.MinGeneration, when(d.LastRelease))
		}
		return tw.Flush()

	case "device":
		if len(pos) < 2 {
			return fmt.Errorf("usage: tpm2-kira-vault device show|revoke|unrevoke|unlock DEVICE, or device mode DEVICE auto|approve")
		}
		var d server.DeviceView
		switch pos[0] {
		case "show":
			if err := want(2, "device show DEVICE"); err != nil {
				return err
			}
			if err := c.do("GET", "/v1/devices/"+esc(pos[1]), nil, &d); err != nil {
				return err
			}
		case "revoke", "unrevoke", "unlock":
			if err := want(2, "device "+pos[0]+" DEVICE"); err != nil {
				return err
			}
			if err := c.do("POST", "/v1/devices/"+esc(pos[1])+"/"+pos[0], nil, &d); err != nil {
				return err
			}
		case "mode":
			if err := want(3, "device mode DEVICE auto|approve"); err != nil {
				return err
			}
			if err := c.do("POST", "/v1/devices/"+esc(pos[1])+"/mode", server.ModeRequest{Mode: pos[2]}, &d); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown device command %q", pos[0])
		}
		printDevice(stdout, &d)
		return nil

	case "requests":
		if err := want(0, "requests"); err != nil {
			return err
		}
		var list []server.RequestView
		if err := c.do("GET", "/v1/requests", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REQUEST\tDEVICE\tNAME\tSTATE\tPEPPER\tGENERATION\tFROM\tEXPIRES")
		for _, q := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", q.ID, q.DeviceID, q.Name, q.State, yesNo(q.Pepper), q.Generation, q.Remote, q.Expires.Local().Format(time.TimeOnly))
		}
		return tw.Flush()

	case "request":
		if err := want(2, "request approve|deny ID"); err != nil {
			return err
		}
		if pos[0] != "approve" && pos[0] != "deny" {
			return fmt.Errorf("unknown request command %q", pos[0])
		}
		var q server.RequestView
		// A device enrolled with a pepper is approved over the operator
		// interface, which carries the pepper; the CLI does not take one.
		if err := c.do("POST", "/v1/requests/"+esc(pos[1])+"/"+pos[0], struct{}{}, &q); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Request %s of device %s: %s. The machine is answered when it asks again.\n", q.ID, q.DeviceID, q.State)
		return nil

	case "operators":
		if err := want(0, "operators"); err != nil {
			return err
		}
		var list []server.OperatorView
		if err := c.do("GET", "/v1/operators", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "OPERATOR\tCREATED")
		for _, o := range list {
			fmt.Fprintf(tw, "%s\t%s\n", o.Name, o.Created.Local().Format(time.DateTime))
		}
		return tw.Flush()

	case "operator":
		if err := want(2, "operator add|remove NAME"); err != nil {
			return err
		}
		switch pos[0] {
		case "add":
			var o server.OperatorAdded
			if err := c.do("POST", "/v1/operators", server.OperatorRequest{Name: pos[1]}, &o); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Operator %s, token (shown this once):\n\n  %s\n\n", o.Name, o.Token)
			fmt.Fprintf(stdout, "  pin:       %s\n  for curl:  --pinnedpubkey %s\n", o.Pin, o.CurlPin)
			if o.URL == "" {
				fmt.Fprintln(stdout, "\nThe operator interface is off: tpm2-kira-vault config set operator-listen :8444, with serve stopped.")
			} else {
				fmt.Fprintf(stdout, "  URL:       %s\n\nFor example:\n\n  %s\n", o.URL, o.Example)
			}
			return nil
		case "remove":
			if err := c.do("DELETE", "/v1/operators/"+esc(pos[1]), nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Operator %s removed: its token no longer works.\n", pos[1])
			return nil
		}
		return fmt.Errorf("unknown operator command %q", pos[0])

	case "audit":
		if err := want(0, "audit [--follow]"); err != nil {
			return err
		}
		path := "/v1/audit"
		if *follow {
			path += "?follow=1"
		}
		rsp, err := c.send("GET", path, nil)
		if err != nil {
			return err
		}
		defer rsp.Body.Close()
		sc := bufio.NewScanner(rsp.Body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			fmt.Fprintln(stdout, formatEntry(sc.Bytes()))
		}
		return sc.Err()
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func deviceState(d *server.DeviceView) string {
	var s []string
	if d.Revoked {
		s = append(s, "revoked")
	}
	if d.Locked {
		s = append(s, "locked")
	}
	if len(s) == 0 {
		return "active"
	}
	return strings.Join(s, ",")
}

func when(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format(time.DateTime)
}

func printDevice(w io.Writer, d *server.DeviceView) {
	fmt.Fprintf(w, "device:          %s\n", d.ID)
	fmt.Fprintf(w, "name:            %s\n", d.Name)
	fmt.Fprintf(w, "keyslot label:   %s\n", d.Label)
	fmt.Fprintf(w, "mode:            %s\n", d.Mode)
	fmt.Fprintf(w, "pepper:          %s\n", yesNo(d.Pepper))
	fmt.Fprintf(w, "state:           %s\n", deviceState(d))
	fmt.Fprintf(w, "failures:        %d in a row\n", d.Failures)
	fmt.Fprintf(w, "min generation:  %d\n", d.MinGeneration)
	fmt.Fprintf(w, "machine PCRs:    %s (bank 0x%04x)\n", formatPCRs(d.Selection.Indices), d.Selection.Alg)
	fmt.Fprintf(w, "vault PCRs:      %s\n", formatPCRs(d.VaultPCRs))
	fmt.Fprintf(w, "enrolled:        %s\n", d.EnrolledAt.Local().Format(time.DateTime))
	fmt.Fprintf(w, "last release:    %s\n", when(d.LastRelease))
}

// formatEntry is an audit line for a person; a line that does not parse
// is printed as it is.
func formatEntry(line []byte) string {
	var e state.Entry
	if json.Unmarshal(line, &e) != nil {
		return string(line)
	}
	parts := []string{e.Time.Local().Format(time.DateTime), e.Event}
	if e.Result != "" {
		parts = append(parts, e.Result)
	}
	if e.Device != "" {
		dev := e.Device
		if e.Name != "" {
			dev += " (" + e.Name + ")"
		}
		parts = append(parts, dev)
	} else if e.Name != "" {
		parts = append(parts, e.Name)
	}
	if e.Request != "" {
		parts = append(parts, "request "+e.Request)
	}
	if e.Actor != "" {
		parts = append(parts, "by "+e.Actor)
	}
	if e.Remote != "" {
		parts = append(parts, "from "+e.Remote)
	}
	if e.Detail != "" {
		parts = append(parts, "- "+e.Detail)
	}
	return strings.Join(parts, "  ")
}
