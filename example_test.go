package opentunnel_test

import (
	"context"
	"net/http"
	"time"

	opentunnel "github.com/darron/go-opentunnel"
)

func ExampleClient_Connect() {
	startup, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()

	lifetime, stop := context.WithCancel(context.Background())
	defer stop()

	client, err := opentunnel.NewClient(opentunnel.ClientOptions{})
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()

	connection, err := client.Connect(startup, opentunnel.ConnectOptions{
		Profile:  "demo",
		Routes:   opentunnel.Routes{"@": "127.0.0.1:8080"},
		Lifetime: lifetime,
	})
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()

	// startup limits only establishment. lifetime controls the running tunnel.
}

func ExampleClient_Listen() {
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{})
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	listener, err := client.Listen(lifetime, opentunnel.ListenOptions{
		Profile: "demo", Routes: []string{"@"}, Lifetime: lifetime,
	})
	if err != nil {
		return
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.TLS holds the actual handshake; RemoteAddr comes from the relay.
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	_ = server.Serve(listener)
}
