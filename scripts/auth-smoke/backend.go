// This backend and WebSocket probe are fixtures for the opt-in public-service
// smoke test. They are never installed with otgo.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	opentunnel "github.com/darron/go-opentunnel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	probe := flag.String("probe", "", "probe a WSS endpoint; token is read from stdin")
	removed := flag.Bool("inspect", false, "inspect a removed tunnel; ID and token JSON are read from stdin")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *removed {
		return inspectRemoved(ctx)
	}
	if *probe != "" {
		if err := websocketProbe(ctx, *probe); err != nil {
			return errors.New("WebSocket probe failed")
		}
		return nil
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	var requests atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats" {
			_, _ = fmt.Fprintln(w, requests.Load())
			return
		}
		requests.Add(1)
		switch r.URL.Path {
		case "/ws":
			c, e := websocket.Accept(w, r, nil)
			if e != nil {
				return
			}
			defer func() { _ = c.CloseNow() }()
			for {
				kind, message, e := c.Read(r.Context())
				if e != nil {
					return
				}
				if c.Write(r.Context(), kind, message) != nil {
					return
				}
			}
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
					if _, e := io.WriteString(w, "data: tick\n\n"); e != nil {
						return
					}
					if http.NewResponseController(w).Flush() != nil {
						return
					}
				}
			}
		case "/redirect":
			w.Header().Set("Location", "http://"+r.Host+"/next?q=1")
			w.WriteHeader(http.StatusFound)
		case "/headers":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Add("Set-Cookie", "__Host-otgo-session=forged; Secure; Path=/")
			w.Header().Add("Set-Cookie", "backend=ok; Path=/")
			_ = json.NewEncoder(w).Encode(struct{ Host, Origin, Referer, Cookie, Authorization, Token, Forwarded, Path, Query string }{r.Host, r.Header.Get("Origin"), r.Header.Get("Referer"), r.Header.Get("Cookie"), r.Header.Get("Authorization"), r.Header.Get("X-Otgo-Token"), r.Header.Get("X-Forwarded-For"), r.URL.EscapedPath(), r.URL.RawQuery})
		case "/upload":
			_, _ = io.Copy(w, http.MaxBytesReader(w, r.Body, 4<<20))
		default:
			_, _ = io.WriteString(w, "protected-backend\n")
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = server.Close() }()
	fmt.Println("http://" + listener.Addr().String())
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func inspectRemoved(ctx context.Context) error {
	var input struct{ ID, Token string }
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return errors.New("invalid inspection input")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	api, err := opentunnel.NewAPI(opentunnel.DefaultAPI, nil, 15*time.Second)
	if err != nil {
		return err
	}
	_, err = api.Get(ctx, input.ID, input.Token)
	var remote *opentunnel.APIError
	if !errors.As(err, &remote) || remote.StatusCode != http.StatusNotFound {
		return errors.New("remote tunnel removal was not confirmed")
	}
	fmt.Println("removed")
	return nil
}

func websocketProbe(ctx context.Context, address string) error {
	secret, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, response, err := websocket.Dial(ctx, address, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + strings.TrimSpace(secret)}}})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return err
	}
	defer func() { _ = c.CloseNow() }()
	if err = c.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		return err
	}
	_, body, err := c.Read(ctx)
	if err != nil || string(body) != "ping" {
		return fmt.Errorf("unexpected echo")
	}
	fmt.Println("ready")
	_, _, err = c.Read(ctx)
	if err == nil || ctx.Err() != nil {
		return fmt.Errorf("revocation did not close the connection")
	}
	fmt.Println("revoked")
	return nil
}
