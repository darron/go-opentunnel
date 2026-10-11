package authproxy

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestSetupCompletionCarriesSelectedCommandEscapesHTMLAndDiscardsSecrets(t *testing.T) {
	s, out, calls := setupFixture(t)
	// A file path is operator input, not executable HTML or JavaScript.
	command := `otgo proxy --profile inbox --auth-config '/tmp/<script>alert("canary")</script>/auth.json'`
	s.launch = SetupLaunch{Profile: "inbox", Command: command}
	cookie := startRegistration(t, s)
	w := setupCallback(s, cookie, s.state)
	if w.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatal("setup did not finish")
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("completion response lost privacy headers")
	}
	match := regexp.MustCompile(`<pre[^>]*id="launch-command"[^>]*>([\s\S]*?)</pre>`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 || html.UnescapeString(match[1]) != command {
		t.Fatal("completion command missing or changed")
	}
	if strings.Contains(w.Body.String(), `<script>alert("canary")</script>`) {
		t.Fatal("path became executable HTML")
	}
	for _, secret := range []string{"new-secret", "discard-private-key", "discard-webhook-secret", "registration-code", s.state, cookie.Value} {
		if strings.Contains(w.Body.String()+out.String(), secret) {
			t.Fatal("completion leaked setup credentials")
		}
	}
	scripts := regexp.MustCompile(`<script>([\s\S]*?)</script>`).FindAllStringSubmatch(w.Body.String(), -1)
	if len(scripts) != 1 {
		t.Fatal("unexpected executable script")
	}
	// Hash the bytes actually sent, not the source file used to make the header.
	sum := sha256.Sum256([]byte(scripts[0][1]))
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatal("clipboard script is blocked or arbitrary scripts allowed")
	}
	if w := setupCallback(s, cookie, s.state); w.Code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatal("completion allowed replay")
	}
}

func TestOwnedPagesEscapeLoginErrorsAndKeepBrowserGateClosed(t *testing.T) {
	for _, github := range []bool{false, true} {
		w := httptest.NewRecorder()
		renderLogin(w, publicRequest("GET", "/__otgo/login"), github, `<script>error-canary</script>`)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), `<script>error-canary</script>`) {
			t.Fatal("login message became HTML or gate returned success")
		}
		if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src") {
			t.Fatal("login acquired script execution")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != CSRFCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
			t.Fatal("login changed CSRF protection")
		}
	}
}
