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
	"path/filepath"
	"strings"
	"time"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

type authFlags struct {
	commonFlags
	configPath, tokenPath string
}

func (a *authFlags) bind(fs *flag.FlagSet) {
	a.commonFlags.bind(fs)
	fs.StringVar(&a.configPath, "auth-config", "", "protected auth config file (default: XDG profile)")
	fs.StringVar(&a.tokenPath, "token-file", "", "machine token registry (default: XDG profile)")
}
func (a authFlags) paths() (authproxy.Paths, error) {
	return authproxy.ResolvePaths(a.profile, a.dataDir, a.configPath, a.tokenPath)
}
func (a authFlags) apiOrigin() (string, error) {
	api := a.api
	if api == "" {
		api = opentunnel.DefaultAPI
	}
	return authproxy.APIOrigin(api)
}
func (a authFlags) profileLock(paths authproxy.Paths) string {
	return filepath.Join(paths.TunnelRoot, a.profile, "otgo-proxy")
}
func (a authFlags) clientAt(paths authproxy.Paths) (*opentunnel.Client, error) {
	return opentunnel.NewClient(opentunnel.ClientOptions{API: a.api, Storage: opentunnel.NewFileStorage(paths.TunnelRoot), RequestTimeout: a.requestTimeout})
}
func (a authFlags) binding(id opentunnel.Identity) (authproxy.Binding, error) {
	origin, e := a.apiOrigin()
	return authproxy.Binding{TunnelID: id.ID, Hostname: id.Hostname, APIOrigin: origin}, e
}
func parseAuthFlags(fs *flag.FlagSet, args []string, a *authFlags) error {
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if a.requestTimeout < 0 {
		return errors.New("request-timeout must not be negative")
	}
	if a.profile == "" {
		a.profile = "default"
	}
	return nil
}
func runAuth(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		_, e := io.WriteString(out, "Usage: otgo auth <init|github|paths|reset|token create|token list|token revoke> [flags]\n")
		return e
	}
	name := args[0]
	args = args[1:]
	if name == "token" {
		if len(args) == 0 {
			return errors.New("token requires create, list or revoke")
		}
		name = "token " + args[0]
		args = args[1:]
	}
	switch name {
	case "init", "github", "paths", "reset", "token create", "token list", "token revoke":
	default:
		return errors.New("unknown auth command")
	}
	fs := newFlagSet("auth "+name, errout)
	var a authFlags
	a.bind(fs)
	var upstream, id, clientID string
	var users nameFlags
	var clientSecretStdin bool
	var passwordStdin, generate, replace bool
	ttl := time.Hour
	timeout := defaultProvisionTimeout
	if name == "init" {
		fs.StringVar(&upstream, "upstream", "", "fixed backend origin (HTTPS or loopback HTTP)")
		fs.BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin instead of generating one")
		fs.BoolVar(&generate, "generate-password", false, "generate and show a password once (also the default)")
		fs.BoolVar(&replace, "replace", false, "replace existing setup and revoke its machine tokens")
		fs.DurationVar(&timeout, "timeout", timeout, "overall provisioning timeout")
	}
	if name == "github" {
		fs.Var(&users, "allow-user", "approved GitHub username (repeatable)")
		fs.StringVar(&clientID, "client-id", "", "existing OAuth/GitHub App client ID")
		fs.BoolVar(&clientSecretStdin, "client-secret-stdin", false, "read the existing client secret from stdin")
		fs.DurationVar(&timeout, "timeout", 10*time.Minute, "overall setup timeout")
	}
	if name == "token create" {
		fs.DurationVar(&ttl, "ttl", ttl, "token lifetime (positive, at most 24h)")
	}
	if name == "token revoke" {
		fs.StringVar(&id, "id", "", "public token ID to revoke")
	}
	if e := parseAuthFlags(fs, args, &a); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	if name == "token create" && (ttl <= 0 || ttl > 24*time.Hour) {
		return errors.New("token lifetime must be positive and at most 24 hours")
	}
	paths, e := a.paths()
	if e != nil {
		return e
	}
	if name == "paths" {
		if a.json {
			return json.NewEncoder(out).Encode(paths)
		}
		_, e = fmt.Fprintf(out, "auth config: %s\ntoken registry: %s\ntunnel root: %s\n", terminalText(paths.AuthConfig), terminalText(paths.TokenFile), terminalText(paths.TunnelRoot))
		return e
	}
	if name == "github" {
		if len(users) == 0 {
			return errors.New("GitHub setup requires at least one --allow-user")
		}
		if (clientID == "") != (!clientSecretStdin) {
			return errors.New("manual GitHub setup requires --client-id and --client-secret-stdin together")
		}
		var secret string
		if clientSecretStdin {
			var e error
			secret, e = readPasswordInput(ctx, in)
			if e != nil {
				return e
			}
			if len(secret) == 0 || len(secret) > 1024 {
				return errors.New("invalid GitHub client secret length")
			}
		}

		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return authproxy.WithProfileLock(a.profileLock(paths), func() error {
			return authproxy.WithMutationLock(paths.AuthConfig, func() error {
				cfg, e := authproxy.LoadConfig(paths.AuthConfig)
				if e != nil {
					return e
				}
				client, e := a.clientAt(paths)
				if e != nil {
					return e
				}
				defer func() { _ = client.Close() }()
				id, e := client.Get(ctx, a.profile)
				if e != nil {
					return e
				}
				if id == nil {
					return errors.New("profile has no stored tunnel")
				}
				binding, e := a.binding(*id)
				if e != nil {
					return e
				}
				if e = authproxy.ValidateBinding(cfg, binding); e != nil {
					return e
				}
				if clientID == "" {
					return authproxy.RunGitHubSetup(ctx, paths, binding, users, out)
				}
				accounts, e := authproxy.ResolveGitHubUsers(ctx, users)
				if e != nil {
					return e
				}
				cfg.Mode = "github"
				cfg.Password = authproxy.PasswordVerifier{}
				cfg.GitHub = authproxy.GitHubConfig{ClientID: clientID, ClientSecret: secret, Users: accounts}
				if e := authproxy.SaveConfig(paths.AuthConfig, cfg); e != nil {
					return e
				}
				_, e = fmt.Fprintf(out, "GitHub login configured for https://%s; callback: https://%s/__otgo/github/callback\n", terminalText(binding.Hostname), terminalText(binding.Hostname))
				return e
			})
		})
	}

	if name == "reset" {
		return authproxy.WithProfileLock(a.profileLock(paths), func() error {
			if e := authproxy.Reset(paths); e != nil {
				return e
			}
			_, e := fmt.Fprintln(out, "removed local auth files; tunnel and GitHub App retained")
			return e
		})
	}
	if name == "init" {
		if _, e := a.apiOrigin(); e != nil {
			return e
		}
		if passwordStdin && generate {
			return errors.New("choose password-stdin or generate-password")
		}
		// Validate the complete origin and password before provisioning any remote resources.
		if e := authproxy.ValidateUpstream(upstream); e != nil {
			return e
		}
		var password string
		if passwordStdin {
			input, e := readPasswordInput(ctx, in)
			if e != nil {
				return errors.New("cannot read password")
			}
			password = input
		} else {
			password, e = authproxy.GeneratePassword()
			if e != nil {
				return e
			}
		}
		verifier, e := authproxy.NewPasswordVerifier([]byte(password))
		if e != nil {
			return e
		}
		if _, e := os.Lstat(paths.AuthConfig); e == nil && !replace {
			return errors.New("auth setup already exists; use --replace while proxy is stopped")
		}
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return authproxy.WithProfileLock(a.profileLock(paths), func() error {
			return authproxy.WithMutationLock(paths.AuthConfig, func() error {
				if _, e := os.Lstat(paths.AuthConfig); e == nil && !replace {
					return errors.New("auth setup already exists; use --replace while proxy is stopped")
				}
				client, e := a.clientAt(paths)
				if e != nil {
					return e
				}
				defer func() { _ = client.Close() }()
				identity, e := client.Ensure(ctx, a.profile)
				if e != nil {
					return e
				}
				binding, e := a.binding(*identity)
				if e != nil {
					return e
				}
				cfg := authproxy.Config{Binding: binding, Upstream: upstream, Mode: "password", Password: verifier}
				// A missing config can leave an older backend's token registry.
				// Every initialization establishes a new authorization boundary.
				if e := authproxy.ResetTokens(paths.TokenFile); e != nil {
					return e
				}
				if e := authproxy.SaveConfig(paths.AuthConfig, cfg); e != nil {
					return e
				}
				if a.json {
					result := struct {
						Profile, Hostname, Mode string
						Password                string `json:"password,omitempty"`
					}{Profile: a.profile, Hostname: identity.Hostname, Mode: "password"}
					if !passwordStdin {
						result.Password = password
					}
					// #nosec G117 -- Explicit setup returns the generated password exactly once.
					return json.NewEncoder(out).Encode(result)
				}
				if _, e := fmt.Fprintf(out, "configured %s: https://%s\n", a.profile, terminalText(identity.Hostname)); e != nil {
					return e
				}
				if !passwordStdin {
					_, e = fmt.Fprintf(out, "password (shown once): %s\n", password)
				}
				return e
			})
		})
	}
	return authproxy.WithMutationLock(paths.AuthConfig, func() error {
		cfg, e := authproxy.LoadConfig(paths.AuthConfig)
		if e != nil {
			return e
		}
		client, e := a.clientAt(paths)
		if e != nil {
			return e
		}
		defer func() { _ = client.Close() }()
		identity, e := client.Get(ctx, a.profile)
		if e != nil {
			return e
		}
		if identity == nil {
			return errors.New("profile has no stored tunnel; run auth setup")
		}
		b, e := a.binding(*identity)
		if e != nil {
			return e
		}
		if e = authproxy.ValidateBinding(cfg, b); e != nil {
			return e
		}
		tokens := authproxy.NewTokenStore(paths.TokenFile)
		switch name {
		case "token create":
			secret, id, e := tokens.Create(ttl)
			if e != nil {
				return e
			}
			if a.json {
				return json.NewEncoder(out).Encode(struct {
					Token string `json:"token"`
					ID    string `json:"id"`
				}{secret, id})
			}
			_, e = fmt.Fprintf(out, "id: %s\ntoken (shown once): %s\n", id, secret)
			return e
		case "token list":
			entries, e := tokens.List()
			if e != nil {
				return e
			}
			if a.json {
				return json.NewEncoder(out).Encode(entries)
			}
			for _, t := range entries {
				if _, e := fmt.Fprintf(out, "%s expires=%s\n", t.ID, t.Expires.Format(time.RFC3339)); e != nil {
					return e
				}
			}
			return nil
		default:
			if id == "" {
				return errors.New("token revoke requires --id")
			}
			if e := tokens.Revoke(id); e != nil {
				return e
			}
			_, e = fmt.Fprintln(out, "revoked", terminalText(id))
			return e
		}
	})
}

func readPasswordInput(ctx context.Context, in io.Reader) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		line, e := bufio.NewReader(io.LimitReader(in, 1026)).ReadString('\n')
		if e != nil && !errors.Is(e, io.EOF) {
			done <- result{err: errors.New("cannot read password")}
			return
		}
		done <- result{value: strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		if c, ok := in.(io.Closer); ok && in != os.Stdin {
			_ = c.Close()
			<-done
		}
		// Native terminal reads may not unblock on Close; process exit owns that read.
		return "", ctx.Err()
	}
}
