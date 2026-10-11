package authproxy

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// This opt-in fixture renders real pages for browser checks. It uses synthetic
// credentials and never starts a tunnel or contacts GitHub.
func TestVisualPreview(t *testing.T) {
	dir := os.Getenv("OTGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set OTGO_UI_PREVIEW_DIR to render a browser fixture")
	}
	save := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		b, e := json.Marshal(struct {
			Headers map[string][]string
			Body    string
		}{w.Header(), w.Body.String()})
		if e != nil {
			t.Fatal(e)
		}
		// #nosec G703 -- Opt-in test fixture directory selected by the developer; names are fixed below.
		if e := os.WriteFile(filepath.Join(dir, name+".json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"github-login", "password-login"} {
		w := httptest.NewRecorder()
		renderLogin(w, publicRequest("GET", "/__otgo/login"), name == "github-login", "")
		save(name, w)
	}
	w := httptest.NewRecorder()
	ownedFormHeaders(w)
	_ = pages.ExecuteTemplate(w, "setup", "fixture-csrf")
	save("setup", w)
	w = httptest.NewRecorder()
	ownedHeaders(w)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'")
	_ = pages.ExecuteTemplate(w, "manifest", struct{ State, Manifest string }{"fixture-state", "{}"})
	save("manifest", w)
	s, _, _ := setupFixture(t)
	s.launch = SetupLaunch{Profile: "inbox", Command: "otgo proxy --profile inbox"}
	cookie := startRegistration(t, s)
	save("complete", setupCallback(s, cookie, s.state))
	s, _, _ = setupFixture(t)
	s.launch = SetupLaunch{Profile: "inbox", Command: "otgo proxy --profile inbox --data-dir '/Users/example/Private files/tunnels' --auth-config '/Users/example/Private files/auth.json' --token-file '/Users/example/Private files/tokens.json' --request-timeout 7s"}
	cookie = startRegistration(t, s)
	save("complete-long", setupCallback(s, cookie, s.state))
	w = httptest.NewRecorder()
	ownedFormHeaders(w)
	_ = pages.ExecuteTemplate(w, "logout", "fixture-csrf")
	save("logout", w)
}
