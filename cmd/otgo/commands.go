package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/darron/go-opentunnel"
)

const usage = `Usage: otgo <command> [flags]

Commands:
  profiles                 List profiles
  list                     List stored tunnels
  get                      Show a stored tunnel
  pending                  Show a pending tunnel request
  create                   Create and provision a tunnel
  resume                   Resume pending provisioning
  ensure                   Reuse or provision a tunnel
  remove                   Delete a tunnel
  inspect                  Fetch public metadata from the remote API
  connect                  Run a tunnel connection
  listen                   Serve an HTTP diagnostic handler directly over tunnel TLS

All command flags follow the command. Common flags are --api, --data-dir,
--profile, --json, and --request-timeout. Run ` + "`otgo <command> --help`" + ` for command flags.
`

type commonFlags struct {
	api            string
	dataDir        string
	profile        string
	json           bool
	requestTimeout time.Duration
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.api, "api", "", "OpenTunnel API base URL")
	fs.StringVar(&c.dataDir, "data-dir", "", "storage directory (default: XDG OpenTunnel directory)")
	fs.StringVar(&c.profile, "profile", "default", "storage profile")
	fs.BoolVar(&c.json, "json", false, "write JSON output")
	fs.DurationVar(&c.requestTimeout, "request-timeout", 0, "per-request timeout (0 uses the client default)")
}

func (c commonFlags) client() (*opentunnel.Client, error) {
	var store opentunnel.Storage
	var err error
	if c.dataDir != "" {
		store = opentunnel.NewFileStorage(c.dataDir)
	} else {
		store, err = opentunnel.NewXDGStorage()
		if err != nil {
			return nil, err
		}
	}
	return opentunnel.NewClient(opentunnel.ClientOptions{API: c.api, Storage: store, RequestTimeout: c.requestTimeout})
}

func newFlagSet(name string, errout io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errout)
	return fs
}

func runCommand(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(out, usage)
		return err
	}
	switch args[0] {
	case "profiles", "list", "get", "pending", "create", "resume", "ensure", "remove", "inspect", "connect", "listen":
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
	return runNamed(ctx, args[0], args[1:], in, out, errout)
}

func runNamed(ctx context.Context, name string, args []string, in io.Reader, out, errout io.Writer) error {
	fs := newFlagSet(name, errout)
	var common commonFlags
	common.bind(fs)
	var timeout time.Duration
	var routes routeFlags
	var listenNames nameFlags
	var interactive bool
	if name == "create" || name == "resume" || name == "ensure" {
		fs.DurationVar(&timeout, "timeout", 2*time.Minute, "overall provisioning timeout (0 disables it)")
	}
	if name == "listen" {
		fs.Var(&listenNames, "route", "SNI route name (repeatable, e.g. @ or api)")
		fs.DurationVar(&timeout, "timeout", 0, "overall listener timeout (0 runs until cancelled)")
	}
	if name == "connect" {
		fs.Var(&routes, "route", "route in name=host:port form (repeatable)")
		fs.BoolVar(&interactive, "interactive", false, "read status, routes, and quit commands from stdin")
		fs.DurationVar(&timeout, "timeout", 0, "overall connection timeout (0 keeps the connection running until cancelled)")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if common.requestTimeout < 0 {
		return errors.New("request-timeout must not be negative")
	}
	if timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	commandCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		commandCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	write := &lockedWriter{w: out}
	writeErr := &lockedWriter{w: errout}
	if name == "profiles" {
		profiles, err := client.Profiles(commandCtx)
		return printValue(write, common.json, profiles, err)
	}
	if name == "list" {
		tunnels, err := client.List(commandCtx)
		return printValue(write, common.json, tunnels, err)
	}
	if name == "get" {
		identity, err := client.Get(commandCtx, common.profile)
		return printPointer(write, common.json, identity, err)
	}
	if name == "pending" {
		pending, err := client.Pending(commandCtx, common.profile)
		return printPointer(write, common.json, pending, err)
	}
	if name == "remove" {
		if err := client.Remove(commandCtx, common.profile); err != nil {
			return err
		}
		if common.json {
			return json.NewEncoder(write).Encode(struct {
				Profile string `json:"profile"`
				Removed bool   `json:"removed"`
			}{Profile: common.profile, Removed: true})
		}
		_, err := fmt.Fprintln(write, "removed", terminalText(common.profile))
		return err
	}
	if name == "inspect" {
		identity, err := client.Get(commandCtx, common.profile)
		if err != nil {
			return err
		}
		if identity == nil {
			return fmt.Errorf("profile %q has no stored tunnel", common.profile)
		}
		info, err := client.API().Get(commandCtx, identity.ID, identity.Token)
		return printValue(write, common.json, info, err)
	}
	if name == "create" || name == "resume" || name == "ensure" {
		options := opentunnel.ProvisionOptions{}
		progressErr := func() error { return nil }
		if !common.json {
			options.OnProgress, progressErr = provisionProgressReporter(writeErr)
		}
		var identity *opentunnel.Identity
		switch name {
		case "create":
			identity, err = client.Create(commandCtx, common.profile, options)
		case "resume":
			identity, err = client.Resume(commandCtx, common.profile, options)
		default:
			identity, err = client.Ensure(commandCtx, common.profile)
		}
		if err := progressErr(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		return printPointer(write, common.json, identity, nil)
	}
	if name == "listen" {
		return listen(commandCtx, client, common.profile, listenNames, common.json, write)
	}
	return connect(commandCtx, client, common.profile, routes, interactive, common.json, in, write, writeErr)
}

func provisionProgressReporter(errout io.Writer) (func(opentunnel.ProvisionStage), func() error) {
	var writeErr error
	return func(stage opentunnel.ProvisionStage) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintln(errout, stage)
	}, func() error { return writeErr }
}

func printValue[T any](out io.Writer, asJSON bool, value T, err error) error {
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(out).Encode(value)
	}
	// Use explicit public fields: default struct formatting would expose
	// credentials that JSON omits.
	switch v := any(value).(type) {
	case []string:
		for _, profile := range v {
			if _, err := fmt.Fprintln(out, terminalText(profile)); err != nil {
				return err
			}
		}
		return nil
	case []opentunnel.StoredTunnel:
		for _, item := range v {
			if _, err := fmt.Fprintf(out, "%s\t%s\t%s\n", terminalText(item.Profile), terminalText(item.Tunnel.ID), terminalText(item.Tunnel.Hostname)); err != nil {
				return err
			}
		}
		return nil
	case opentunnel.Identity:
		_, err = fmt.Fprintf(out, "id: %s\nhostname: %s\ncertificate expiry: %s\n", terminalText(v.ID), terminalText(v.Hostname), v.CertificateExpiry.Format(time.RFC3339))
		return err
	case opentunnel.PendingIdentity:
		_, err = fmt.Fprintf(out, "id: %s\nhostname: %s\nstate: pending\n", terminalText(v.ID), terminalText(v.Hostname))
		return err
	case opentunnel.TunnelInfo:
		_, err = fmt.Fprintf(out, "id: %s\nhostname: %s\nstate: %s\n", terminalText(v.ID), terminalText(v.Hostname), terminalText(v.State))
		return err
	default:
		return fmt.Errorf("cannot safely render %T without --json", value)
	}
}

func printPointer[T any](out io.Writer, asJSON bool, value *T, err error) error {
	if err != nil {
		return err
	}
	if value == nil {
		if asJSON {
			return json.NewEncoder(out).Encode(nil)
		}
		_, err = fmt.Fprintln(out, "not found")
		return err
	}
	return printValue(out, asJSON, *value, nil)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

type routeFlags []string

func (r *routeFlags) String() string { return strings.Join(*r, ",") }
func (r *routeFlags) Set(v string) error {
	if _, _, err := parseRoute(v); err != nil {
		return err
	}
	*r = append(*r, v)
	return nil
}
func (r routeFlags) routes() (opentunnel.Routes, error) {
	result := make(opentunnel.Routes, len(r))
	for _, item := range r {
		name, target, err := parseRoute(item)
		if err != nil {
			return nil, err
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate route %q", name)
		}
		result[name] = target
	}
	return result, nil
}
func parseRoute(value string) (string, string, error) {
	name, target, found := strings.Cut(value, "=")
	if !found || name == "" || target == "" {
		return "", "", fmt.Errorf("route must be name=host:port, got %q", value)
	}
	return name, target, nil
}

func connect(ctx context.Context, client *opentunnel.Client, profile string, values routeFlags, interactive, asJSON bool, in io.Reader, out, errout io.Writer) error {
	routes, err := values.routes()
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return errors.New("connect requires at least one --route name=host:port")
	}
	connection, err := client.Connect(ctx, opentunnel.ConnectOptions{Profile: profile, Routes: routes, Lifetime: ctx})
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	identity := connection.Identity()
	if asJSON {
		if err := json.NewEncoder(out).Encode(struct {
			Type     string              `json:"type"`
			Identity opentunnel.Identity `json:"identity"`
			Routes   opentunnel.Routes   `json:"routes"`
		}{Type: "connected", Identity: identity, Routes: routes}); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(out, "connected https://%s\n", terminalText(identity.Hostname)); err != nil {
			return err
		}
		for name := range routes {
			if name != "@" {
				if _, err := fmt.Fprintf(out, "route %s: https://%s.%s\n", terminalText(name), terminalText(name), terminalText(identity.Hostname)); err != nil {
					return err
				}
			}
		}
	}

	if !interactive {
		for {
			select {
			case event, ok := <-connection.Events():
				if !ok {
					return connection.Err()
				}
				if err := printEvent(out, asJSON, event); err != nil {
					return err
				}
			case <-connection.Done():
				return connection.Err()
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	commands, stopReader := startCommandReader(ctx, in)
	defer stopReader()
	for {
		select {
		case event, ok := <-connection.Events():
			if !ok {
				return connection.Err()
			}
			if err := printEvent(out, asJSON, event); err != nil {
				return err
			}
		case line, ok := <-commands:
			if !ok {
				return nil
			}
			quit, err := processInteractiveCommand(connection, line, asJSON, out, errout)
			if err != nil {
				return err
			}
			if quit {
				return nil
			}
		case <-connection.Done():
			return connection.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func printInteractiveError(errout io.Writer, err error) error {
	_, writeErr := fmt.Fprintln(errout, "interactive:", terminalText(err.Error()))
	return writeErr
}

func startCommandReader(ctx context.Context, in io.Reader) (<-chan string, func()) {
	commands := make(chan string, 1)
	readerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go readCommands(readerCtx, in, commands, done)
	return commands, func() {
		cancel()
		file, isFile := in.(*os.File)
		if isFile && file == os.Stdin {
			// Closing native stdin may not interrupt Read. Leave it to process exit
			// after tunnel cleanup; quit stops scanning directly.
			return
		}
		if closer, ok := in.(io.Closer); ok {
			_ = closer.Close()
			<-done
		}
	}
}

func readCommands(ctx context.Context, in io.Reader, commands chan<- string, done chan<- struct{}) {
	defer close(done)
	defer close(commands)
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		select {
		case commands <- line:
		case <-ctx.Done():
			return
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "quit" {
			return
		}
	}
}

var errQuit = errors.New("interactive quit")

type interactiveConnection interface {
	Status() opentunnel.Status
	SetRoutes(opentunnel.Routes) error
}

func processInteractiveCommand(connection interactiveConnection, line string, asJSON bool, out, errout io.Writer) (bool, error) {
	err := interactiveCommand(connection, line, asJSON, out)
	if errors.Is(err, errQuit) {
		return true, nil
	}
	if err != nil {
		var inputErr interactiveInputError
		if errors.As(err, &inputErr) {
			return false, printInteractiveError(errout, inputErr)
		}
		return false, err
	}
	return false, nil
}

type interactiveInputError struct{ err error }

func (e interactiveInputError) Error() string { return e.err.Error() }
func (e interactiveInputError) Unwrap() error { return e.err }

func interactiveCommand(connection interactiveConnection, line string, asJSON bool, out io.Writer) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "status":
		if asJSON {
			return json.NewEncoder(out).Encode(connection.Status())
		}
		return printStatus(out, connection.Status())
	case "quit":
		return errQuit
	case "routes":
		routes := make(opentunnel.Routes, len(fields)-1)
		for _, value := range fields[1:] {
			name, target, err := parseRoute(value)
			if err != nil {
				return interactiveInputError{err: err}
			}
			if _, duplicate := routes[name]; duplicate {
				return interactiveInputError{err: fmt.Errorf("duplicate route %q", name)}
			}
			routes[name] = target
		}
		if err := connection.SetRoutes(routes); err != nil {
			if errors.Is(err, opentunnel.ErrInvalid) || errors.Is(err, opentunnel.ErrRouteInUse) {
				return interactiveInputError{err: err}
			}
			return err
		}
		return nil
	default:
		return interactiveInputError{err: fmt.Errorf("unknown interactive command %q (use status, routes, or quit)", fields[0])}
	}
}
func formatEvent(event opentunnel.Event) string {
	parts := []string{terminalText(event.Type)}
	if event.Attempt != 0 {
		parts = append(parts, fmt.Sprintf("attempt=%d", event.Attempt))
	}
	if event.Delay != 0 {
		parts = append(parts, "delay="+event.Delay.String())
	}
	if event.Session != "" {
		parts = append(parts, "session="+terminalText(event.Session))
	}
	if event.Conn != 0 {
		parts = append(parts, fmt.Sprintf("conn=%d", event.Conn))
	}
	if event.Route != "" {
		parts = append(parts, "route="+terminalText(event.Route))
	}
	if event.Peer != "" {
		parts = append(parts, "peer="+terminalText(event.Peer))
	}
	if event.Reason != "" {
		parts = append(parts, "reason="+terminalText(event.Reason))
	}
	if event.Error != "" {
		parts = append(parts, "error="+terminalText(event.Error))
	}
	if !event.Expiry.IsZero() {
		parts = append(parts, "expiry="+event.Expiry.UTC().Format(time.RFC3339))
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, " ")
}

func printEvent(out io.Writer, asJSON bool, event opentunnel.Event) error {
	if asJSON {
		return json.NewEncoder(out).Encode(event)
	}
	_, err := fmt.Fprintln(out, formatEvent(event))
	return err
}

func printStatus(out io.Writer, status opentunnel.Status) error {
	_, err := fmt.Fprintf(out, "state: %s\nhostname: %s\nconnections: %d\ndropped events: %d\n", terminalText(status.State), terminalText(status.Hostname), status.Connections, status.DroppedEvents)
	return err
}

func terminalText(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return '?'
		}
		return r
	}, value)
}
