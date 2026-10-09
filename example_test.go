package opentunnel_test

import (
	"context"
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
