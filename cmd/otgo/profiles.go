package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

type profileSummary struct {
	Profile  string `json:"profile"`
	URL      string `json:"url,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	Auth     string `json:"auth,omitempty"`
	Status   string `json:"status"`
	Command  string `json:"command,omitempty"`
}

// launchCommand contains only operator-selected flags, never credentials. Quote
// each argument for POSIX shells so storage paths cannot become shell code.
func (a authFlags) launchCommand() string {
	// Copying into a new terminal must not reinterpret relative storage paths.
	if paths, e := a.paths(); e == nil {
		if a.dataDir != "" {
			a.dataDir = paths.TunnelRoot
		}
		if a.configPath != "" {
			a.configPath = paths.AuthConfig
		}
		if a.tokenPath != "" {
			a.tokenPath = paths.TokenFile
		}
	}
	args := []string{"otgo", "proxy", "--profile", a.profile}
	for _, pair := range [][2]string{{"--api", a.api}, {"--data-dir", a.dataDir}, {"--auth-config", a.configPath}, {"--token-file", a.tokenPath}} {
		if pair[1] != "" {
			args = append(args, pair[0], pair[1])
		}
	}
	if a.requestTimeout != 0 {
		args = append(args, "--request-timeout", a.requestTimeout.String())
	}
	return shellCommand(args)
}

func runProfiles(ctx context.Context, args []string, out, errout io.Writer) error {
	fs := newFlagSet("profiles", errout)
	var a authFlags
	a.bind(fs)
	var namesOnly bool
	fs.BoolVar(&namesOnly, "names", false, "print names only (including pending and auth-only profiles)")
	if e := parseAuthFlags(fs, args, &a); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	paths, e := a.paths()
	if e != nil {
		return e
	}
	store := opentunnel.NewFileStorage(paths.TunnelRoot)
	names, e := store.Profiles(ctx)
	if e != nil {
		return e
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		seen[name] = true
	}
	// Only the default XDG auth tree is discoverable. An explicit config belongs
	// to --profile, not to every tunnel in the selected root.
	defaultPaths, e := authproxy.ResolvePaths("default", "", "", "")
	if e != nil {
		return e
	}
	entries, e := os.ReadDir(filepath.Dir(filepath.Dir(defaultPaths.AuthConfig)))
	if e != nil && !os.IsNotExist(e) {
		return errors.New("cannot list saved auth profiles")
	}
	for _, entry := range entries {
		if entry.IsDir() && authproxy.ValidProfile(entry.Name()) {
			seen[entry.Name()] = true
		}
	}
	if a.configPath != "" {
		if _, e := os.Lstat(paths.AuthConfig); e == nil {
			seen[a.profile] = true
		} else if !os.IsNotExist(e) {
			return errors.New("cannot inspect selected auth configuration")
		}
	}
	names = make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	if e := ctx.Err(); e != nil {
		return e
	}
	if namesOnly {
		return printValue(out, a.json, names, nil)
	}
	rows := make([]profileSummary, 0, len(names))
	for _, name := range names {
		if e := ctx.Err(); e != nil {
			return e
		}
		row := profileSummary{Profile: name, Status: "empty"}
		selected := a
		selected.profile = name
		if name != a.profile {
			selected.configPath = ""
			selected.tokenPath = ""
		}
		p, e := selected.paths()
		if e != nil {
			return e
		}
		id, loadErr := store.Load(ctx, name)
		switch {
		case loadErr != nil:
			row.Status = "incomplete"
		case id != nil:
			row.Status = "unprotected"
			row.URL = publicURL(id.Hostname)
		default:
			pending, e := store.LoadPending(ctx, name)
			if e != nil {
				row.Status = "incomplete"
			} else if pending != nil {
				row.Status = "pending"
				row.URL = publicURL(pending.Hostname)
			}
		}
		_, statErr := os.Lstat(p.AuthConfig)
		if statErr == nil {
			cfg, e := authproxy.LoadConfig(p.AuthConfig)
			switch {
			case e != nil:
				row.Status = "invalid-auth"
			case loadErr != nil:
				row.Status = "incomplete"
				row.Auth = cfg.Mode
				row.Upstream = cfg.Upstream
			case id == nil:
				row.Auth = cfg.Mode
				row.Upstream = cfg.Upstream
				if row.Status == "empty" {
					row.Status = "auth-only"
					row.URL = publicURL(cfg.Binding.Hostname)
				}
			default:
				row.Auth = cfg.Mode
				row.Upstream = cfg.Upstream
				origin, e := selected.apiOrigin()
				switch {
				case cfg.Binding.TunnelID != id.ID || cfg.Binding.Hostname != id.Hostname:
					row.Status = "identity-mismatch"
				case selected.api == "" && cfg.Binding.APIOrigin != opentunnel.DefaultAPI:
					// The binding stores the origin, not a possible API base path.
					// Do not invent a command pointing at the wrong endpoint.
					row.Status = "api-required"
				case e != nil || cfg.Binding.APIOrigin != origin:
					row.Status = "api-mismatch"
				default:
					row.Status = "ready"
					row.Command = selected.launchCommand()
				}
			}
		} else if !os.IsNotExist(statErr) {
			row.Status = "invalid-auth"
		}
		rows = append(rows, row)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if a.json {
		return json.NewEncoder(out).Encode(rows)
	}
	if len(rows) == 0 {
		_, e = fmt.Fprintln(out, "No saved profiles.")
		return e
	}
	for _, r := range rows {
		if _, e = fmt.Fprintf(out, "%s (%s)\n", terminalText(r.Profile), r.Status); e != nil {
			return e
		}
		if r.Status == "api-required" {
			if _, e = fmt.Fprintln(out, "  Supply the original --api base URL to show a launch command."); e != nil {
				return e
			}
		}
		for _, pair := range [][2]string{{"URL", r.URL}, {"Backend", r.Upstream}, {"Login", r.Auth}, {"Run", r.Command}} {
			if pair[1] != "" {
				if _, e = fmt.Fprintf(out, "  %s: %s\n", pair[0], terminalText(pair[1])); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func publicURL(host string) string {
	// Stored identity metadata is untrusted. Never render arbitrary terminal links
	// or shell fragments as clickable URLs.
	if host == "" || len(host) > 253 {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if !authproxy.ValidProfile(label) {
			return ""
		}
	}
	return "https://" + host
}
