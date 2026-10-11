package opentunnel_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	opentunnel "github.com/darron/go-opentunnel"
)

func ExampleClient_Connect() {
	startup, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()

	lifetime, stop := signal.NotifyContext(context.Background(), os.Interrupt)
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

	// Releasing startup after attachment does not stop the running tunnel.
	cancelStartup()
	fmt.Println("https://" + connection.Identity().Hostname)
	<-connection.Done() // Ctrl-C cancels lifetime and stops the tunnel.
	if err := connection.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func ExampleClient_Listen() {
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{})
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	lifetime, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	startup, cancelStartup := context.WithTimeout(lifetime, 30*time.Second)
	defer cancelStartup()
	listener, err := client.Listen(startup, opentunnel.ListenOptions{
		Profile: "demo", Routes: []string{"@"}, Lifetime: lifetime,
	})
	if err != nil {
		return
	}
	defer func() { _ = listener.Close() }()
	cancelStartup() // lifetime continues to own the listener after startup.
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

func ExampleRouteForSNI() {
	route, ok := opentunnel.RouteForSNI("API.demo.opentunnel.xyz", "demo.opentunnel.xyz")
	fmt.Println(route, ok)
	route, ok = opentunnel.RouteForSNI("demo.opentunnel.xyz", "demo.opentunnel.xyz")
	fmt.Println(route, ok)
	_, ok = opentunnel.RouteForSNI("other.example", "demo.opentunnel.xyz")
	fmt.Println(ok)
	// Output:
	// api true
	// @ true
	// false
}

func ExampleValidateRoutes() {
	err := opentunnel.ValidateRoutes(opentunnel.Routes{
		"@":   "127.0.0.1:8080",
		"api": "[::1]:9090",
	})
	fmt.Println(err)
	// Output: <nil>
}

func ExampleNewMemoryStorage() {
	ctx := context.Background()
	store := opentunnel.NewMemoryStorage()
	if err := store.Save(ctx, "demo", opentunnel.Identity{
		ID: "example-id", Hostname: "demo.opentunnel.xyz",
	}); err != nil {
		fmt.Println(err)
		return
	}
	identity, err := store.Load(ctx, "demo")
	if err != nil {
		fmt.Println(err)
		return
	}
	if identity != nil {
		fmt.Println(identity.Hostname)
	}
	// Output: demo.opentunnel.xyz
}
