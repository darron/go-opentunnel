package identity_test

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/darron/go-opentunnel/identity"
)

func ExampleVerifyRequest() {
	// Export once locally: otgo auth public-key --profile inbox > otgo-inbox.pub
	// Deploy this trusted file with your backend. Never fetch a key from a request.
	data, err := os.ReadFile("otgo-inbox.pub")
	if err != nil {
		log.Fatal(err)
	}
	key, err := identity.ParsePublicKey(data)
	if err != nil {
		log.Fatal(err)
	}
	options := identity.VerifyOptions{
		Issuer:   "https://example.opentunnel.xyz",
		Audience: "http://127.0.0.1:8000",
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user, err := identity.VerifyRequest(r, key, options)
		if err != nil {
			http.Error(w, "GitHub sign-in required", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, "Hello %s (GitHub ID %s)\n", user.Login, user.ID)
	})
}
