// webapp serves HTTP/WebSocket through a tunnel TLS listener or a loopback target.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/darron/go-opentunnel"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	api := flag.String("api", "", "OpenTunnel API base URL")
	dataDir := flag.String("data-dir", "", "tunnel storage directory (default: XDG)")
	profile := flag.String("profile", "webapp", "tunnel profile")
	forward := flag.Bool("forward", false, "forward tunnel traffic to the loopback HTTP listener")
	localOnly := flag.Bool("local-only", false, "serve only the loopback target; do not create a tunnel")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, "go-opentunnel embedded example") })
	mux.HandleFunc("/request", requestMetadata)
	mux.HandleFunc("/stream", stream)
	mux.HandleFunc("/ws", echo)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	var serverErr <-chan error
	if *localOnly || *forward {
		serverErr = serve(server, *addr)
	}
	if *localOnly {
		return waitServer(ctx, serverErr)
	}
	store, err := exampleStorage(*dataDir)
	if err != nil {
		return err
	}
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{API: *api, Storage: store})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if !*forward {
		listener, err := client.Listen(ctx, opentunnel.ListenOptions{Profile: *profile, Routes: []string{"@"}, Lifetime: ctx})
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		errs := make(chan error, 1)
		go func() { errs <- server.Serve(listener); close(errs) }()
		defer func() { _ = listener.Close(); _ = server.Close(); <-errs }()
		log.Printf("serving handler directly through https://%s", listener.Identity().Hostname)
		return waitConnection(ctx, errs, listener)
	}
	connection, err := client.Connect(ctx, opentunnel.ConnectOptions{Profile: *profile, Routes: opentunnel.Routes{"@": *addr}, Lifetime: ctx})
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	log.Printf("serving %s through https://%s", *addr, connection.Identity().Hostname)
	return waitConnection(ctx, serverErr, connection)
}

func exampleStorage(dataDir string) (opentunnel.Storage, error) {
	if dataDir != "" {
		return opentunnel.NewFileStorage(dataDir), nil
	}
	return opentunnel.NewXDGStorage()
}

func serve(server *http.Server, addr string) <-chan error {
	errs := make(chan error, 1)
	log.Printf("serving loopback example on http://%s", addr)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errs <- err
		}
		close(errs)
	}()
	return errs
}

func waitServer(ctx context.Context, errs <-chan error) error {
	select {
	case <-ctx.Done():
		return nil
	case err, ok := <-errs:
		if !ok {
			return nil
		}
		return err
	}
}

func waitConnection(ctx context.Context, errs <-chan error, connection interface {
	Done() <-chan struct{}
	Err() error
	Events() <-chan opentunnel.Event
}) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-connection.Done():
			return connection.Err()
		case event, ok := <-connection.Events():
			if !ok {
				<-connection.Done()
				return connection.Err()
			}
			log.Printf("tunnel event: %s", event.Type)
		}
	}
}

func stream(w http.ResponseWriter, _ *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for i := 1; i <= 3; i++ {
		_, _ = fmt.Fprintf(w, "chunk %d\n", i)
		flusher.Flush()
		time.Sleep(250 * time.Millisecond)
	}
}

func echo(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	for {
		typ, body, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if err := conn.Write(r.Context(), typ, body); err != nil {
			return
		}
	}
}

// requestMetadata shows the transport state without interpreting proxy headers.
func requestMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	state := struct {
		TLS  bool   `json:"tls"`
		SNI  string `json:"sni"`
		Peer string `json:"peer"`
	}{Peer: r.RemoteAddr}
	if r.TLS != nil {
		state.TLS = r.TLS.HandshakeComplete
		state.SNI = r.TLS.ServerName
	}
	_ = json.NewEncoder(w).Encode(state)
}
