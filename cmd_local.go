package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mrwiora/tpm2-kira-vault/internal/keys"
	"github.com/mrwiora/tpm2-kira-vault/internal/server"
	"github.com/mrwiora/tpm2-kira-vault/internal/state"
	"github.com/mrwiora/tpm2-kira-vault/internal/tlsutil"
)

// ── init ─────────────────────────────────────────────────────────────────

func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	listen := fs.String("listen", ":8443", "machine-facing HTTPS address")
	pubURL := fs.String("url", "", "the URL machines reach the vault at (default https://HOSTNAME:PORT)")
	pcrsFlag := fs.String("pcrs", "7", "the vault's own PCRs the device keys are sealed to (SHA-256 bank)")
	tpmPath := fs.String("tpm", state.DefaultTPM, "TPM device or simulator socket")
	sock := fs.String("admin-socket", state.DefaultAdminSocket, "the admin interface's Unix socket")
	opListen := fs.String("operator-listen", "", "the operator interface's HTTPS address (default: off)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("init takes no arguments, got %q", pos)
	}
	pcrs, err := parsePCRs(*pcrsFlag)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", *listen, err)
	}
	if err := checkOperatorListen(*opListen, *listen); err != nil {
		return err
	}
	if *pubURL == "" {
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		*pubURL = "https://" + net.JoinHostPort(host, port)
	}
	u, err := url.Parse(*pubURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("--url %q: an https URL with a host", *pubURL)
	}
	*pubURL = strings.TrimRight(*pubURL, "/")

	d := state.Dir{Path: *dir}
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if d.Initialised() {
		return fmt.Errorf("%s holds a vault already", *dir)
	}

	// The TPM must seal and unseal before anything depends on it.
	sealer := newSealer(*tpmPath)
	probe, err := keys.NewKey()
	if err != nil {
		return err
	}
	sl, err := sealer.Seal(probe, pcrs)
	if err != nil {
		return fmt.Errorf("the TPM %s: %w", *tpmPath, err)
	}
	back, err := sealer.Unseal(sl)
	if err != nil || !bytes.Equal(back, probe) {
		return fmt.Errorf("the TPM %s does not unseal what it sealed: %v", *tpmPath, err)
	}
	keys.Wipe(back)

	if err := d.Create(); err != nil {
		return err
	}
	now := time.Now()
	if err := tlsutil.Write(d, u.Hostname(), now); err != nil {
		return err
	}
	pin, err := tlsutil.Pin(d)
	if err != nil {
		return err
	}
	rk, err := keys.NewRecoveryKey()
	if err != nil {
		return err
	}
	defer rk.Wipe()
	rpub, err := rk.Public()
	if err != nil {
		return err
	}
	cfg := &state.Config{Listen: *listen, URL: *pubURL, PCRs: pcrs, TPM: *tpmPath, AdminSocket: *sock, OperatorListen: *opListen, RecoveryPublic: rpub}
	if err := d.SaveConfig(cfg); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "init", Actor: "admin", Result: "done", Detail: fmt.Sprintf("url %s, PCRs %s", cfg.URL, formatPCRs(pcrs))}); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Initialised the vault in %s.\n\n", *dir)
	fmt.Fprintf(stdout, "  URL:   %s\n  pin:   %s  (for curl: %s)\n  PCRs:  %s (SHA-256)\n  TPM:   %s\n", cfg.URL, pin, tlsutil.CurlPin(pin), formatPCRs(pcrs), cfg.TPM)
	if u := server.OperatorURL(cfg); u != "" {
		fmt.Fprintf(stdout, "  operator interface: %s (tokens: tpm2-kira-vault operator add NAME)\n", u)
	}
	fmt.Fprintln(stdout)
	if len(pcrs) == 0 {
		fmt.Fprintln(stderr, noPCRWarning)
	}
	fmt.Fprintf(stdout, "Vault recovery key (shown this once: write it down and keep it offline):\n\n    %s\n\n", rk.String())
	fmt.Fprintln(stdout, "It reseals the device keys after a firmware or Secure Boot change of this vault")
	fmt.Fprintln(stdout, "(tpm2-kira-vault reseal). Without it and without the vault's boot state, no device")
	fmt.Fprintln(stdout, "is released any more, and every machine needs its recovery passphrase.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Next: systemctl enable --now tpm2-kira-vault, then tpm2-kira-vault token create --name NAME.")
	return nil
}

// logOnce writes one audit entry from a command that runs without serve.
func logOnce(d state.Dir, e state.Entry) error {
	a, err := state.OpenAudit(d.AuditPath(), nil)
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Log(e)
}

// ── serve ────────────────────────────────────────────────────────────────

func cmdServe(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return fmt.Errorf("serve takes no arguments, got %q", pos)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, state.Dir{Path: *dir}, stderr, nil)
}

// serve runs both interfaces until ctx ends. ready, when given, is closed
// once both listen.
func serve(ctx context.Context, d state.Dir, stderr io.Writer, ready chan<- struct{}) error {
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := d.Config()
	if err != nil {
		return err
	}
	cert, pin, err := tlsutil.Load(d)
	if err != nil {
		return err
	}
	audit, err := state.OpenAudit(d.AuditPath(), nil)
	if err != nil {
		return err
	}
	defer audit.Close()
	logger := log.New(stderr, "", 0)
	if len(cfg.PCRs) == 0 {
		logger.Print(noPCRWarning)
	}
	srv := server.New(server.Options{Dir: d, Config: cfg, Sealer: newSealer(cfg.TPM), Audit: audit, Pin: pin, Log: logger})

	base := func(net.Listener) context.Context { return ctx }

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	machine := &http.Server{
		Handler:           srv.MachineHandler(),
		TLSConfig:         tlsutil.ServerConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          logger,
		BaseContext:       base,
	}

	if err := os.MkdirAll(filepath.Dir(cfg.AdminSocket), 0o700); err != nil {
		return err
	}
	os.Remove(cfg.AdminSocket) // left by a serve that is gone: the lock is ours
	old := syscall.Umask(0o177)
	adminLn, err := net.Listen("unix", cfg.AdminSocket)
	syscall.Umask(old)
	if err != nil {
		ln.Close()
		return err
	}
	defer os.Remove(cfg.AdminSocket)
	if err := os.Chmod(cfg.AdminSocket, 0o600); err != nil {
		return err
	}
	admin := &http.Server{Handler: srv.AdminHandler(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: logger, BaseContext: base}

	// The operator interface: its own listener, so that it can be
	// firewalled apart from the machines'.
	var operator *http.Server
	var opLn net.Listener
	if cfg.OperatorListen != "" {
		if opLn, err = net.Listen("tcp", cfg.OperatorListen); err != nil {
			ln.Close()
			adminLn.Close()
			return err
		}
		operator = &http.Server{
			Handler:           srv.OperatorHandler(),
			TLSConfig:         tlsutil.ServerConfig(cert),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          logger,
			BaseContext:       base,
		}
	}

	errc := make(chan error, 3)
	go func() { errc <- machine.ServeTLS(ln, "", "") }()
	go func() { errc <- admin.Serve(adminLn) }()
	if operator != nil {
		go func() { errc <- operator.ServeTLS(opLn, "", "") }()
		logger.Printf("operator interface on %s", cfg.OperatorListen)
	}
	audit.Log(state.Entry{Event: "serve", Result: "started", Detail: "listening on " + cfg.Listen})
	logger.Printf("serving %s on %s (pin %s), admin socket %s", cfg.URL, cfg.Listen, pin, cfg.AdminSocket)
	if ready != nil {
		close(ready)
	}

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	machine.Shutdown(shut)
	admin.Shutdown(shut)
	if operator != nil {
		operator.Shutdown(shut)
	}
	audit.Log(state.Entry{Event: "serve", Result: "stopped"})
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ── config ───────────────────────────────────────────────────────────────

func checkOperatorListen(addr, listen string) error {
	if addr == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("operator-listen %q: %w", addr, err)
	}
	if addr == listen {
		return fmt.Errorf("operator-listen %q is the machines' address: give it its own", addr)
	}
	return nil
}

// cmdConfig changes config.json. It refuses while serve runs, which reads
// the configuration at its start.
func cmdConfig(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 3 || pos[0] != "set" || pos[1] != "operator-listen" {
		return errors.New(`usage: tpm2-kira-vault config set operator-listen ADDR|""`)
	}
	d := state.Dir{Path: *dir}
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := d.Config()
	if err != nil {
		return err
	}
	if err := checkOperatorListen(pos[2], cfg.Listen); err != nil {
		return err
	}
	cfg.OperatorListen = pos[2]
	if err := d.SaveConfig(cfg); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "config", Actor: "admin", Result: "done", Detail: "operator-listen " + strconv.Quote(pos[2])}); err != nil {
		return err
	}
	if pos[2] == "" {
		fmt.Fprintln(stdout, "The operator interface is off from serve's next start.")
	} else {
		fmt.Fprintf(stdout, "The operator interface listens on %s (%s) from serve's next start.\n", pos[2], server.OperatorURL(cfg))
	}
	return nil
}

// ── reseal ───────────────────────────────────────────────────────────────

func cmdReseal(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("reseal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	pcrsFlag := fs.String("pcrs", "", "the vault's PCRs to seal to (default: the configured selection)")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return fmt.Errorf("reseal takes no arguments, got %q", pos)
	}
	d := state.Dir{Path: *dir}
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := d.Config()
	if err != nil {
		return err
	}
	pcrs := cfg.PCRs
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "pcrs" })
	if given {
		if pcrs, err = parsePCRs(*pcrsFlag); err != nil {
			return err
		}
	}
	devices, err := d.Devices()
	if err != nil {
		return err
	}

	line, err := readSecret(stdin, stderr, "Vault recovery key: ")
	if err != nil {
		return err
	}
	rk, err := keys.ParseRecoveryKey(line)
	if err != nil {
		return err
	}
	defer rk.Wipe()
	pub, err := rk.Public()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(pub, cfg.RecoveryPublic) != 1 {
		return errors.New("this is not this vault's recovery key")
	}

	sealer := newSealer(cfg.TPM)
	for _, dev := range devices {
		kdev, err := rk.Open(dev.Recovery, dev.ID)
		if err != nil {
			return fmt.Errorf("device %x (%s): its recovery copy does not open: %w", dev.ID, dev.Name, err)
		}
		sealed, err := sealer.Seal(kdev, pcrs)
		keys.Wipe(kdev)
		if err != nil {
			return fmt.Errorf("device %x (%s): %w", dev.ID, dev.Name, err)
		}
		dev.Sealed = *sealed
		if err := d.SaveDevice(dev); err != nil {
			return err
		}
	}
	cfg.PCRs = pcrs
	if err := d.SaveConfig(cfg); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "reseal", Actor: "admin", Result: "done", Detail: fmt.Sprintf("%d device keys to PCRs %s", len(devices), formatPCRs(pcrs))}); err != nil {
		return err
	}
	if len(pcrs) == 0 {
		fmt.Fprintln(stderr, noPCRWarning)
	}
	fmt.Fprintf(stdout, "Resealed %d device keys to the vault's PCRs %s (SHA-256) as they are now.\n", len(devices), formatPCRs(pcrs))
	return nil
}

// readSecret reads one line: from a terminal without echo, after a
// prompt; otherwise as it comes (a pipe, in tests).
func readSecret(in io.Reader, prompt io.Writer, text string) (string, error) {
	if f, ok := in.(*os.File); ok {
		fd := int(f.Fd())
		if t, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
			fmt.Fprint(prompt, text)
			quiet := *t
			quiet.Lflag &^= unix.ECHO
			quiet.Lflag |= unix.ICANON | unix.ISIG
			if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
				return "", err
			}
			defer func() {
				unix.IoctlSetTermios(fd, unix.TCSETS, t)
				fmt.Fprintln(prompt)
			}()
		}
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("reading the recovery key: %w", err)
	}
	return strings.TrimSpace(line), nil
}
