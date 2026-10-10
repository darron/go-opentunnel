package authproxy

import "fmt"

// Format the owning object rather than relying on nested formatters: fmt does
// not invoke formatting methods when traversing unexported struct fields.
func (Handler) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.Handler{credentials:redacted}"))
}
func (PasswordBrowserAuthenticator) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.PasswordBrowserAuthenticator{credentials:redacted}"))
}
func (GitHubBrowserAuthenticator) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.GitHubBrowserAuthenticator{credentials:redacted}"))
}
func (githubSetup) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.githubSetup{credentials:redacted}"))
}
func (credential) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.credential{redacted}"))
}
func (githubPending) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.githubPending{redacted}"))
}
func (*requestLease) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("authproxy.requestLease{redacted}"))
}
