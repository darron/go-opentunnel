package authproxy

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"net/http"
)

// Pages are self-contained: the loopback setup server stops after saving, so
// its completion page cannot depend on later asset requests.
//
//go:embed ui/*
var pageFiles embed.FS

func pageText(path string) string {
	b, e := pageFiles.ReadFile("ui/" + path)
	if e != nil {
		panic(e)
	}
	return string(b)
}

var pages = template.Must(template.New("pages").Parse(
	`{{define "style"}}` + pageText("style.css") + `{{end}}` +
		`{{define "mark"}}` + pageText("mark.svg") + `{{end}}` +
		`{{define "github"}}` + pageText("github.svg") + `{{end}}` +
		`{{define "copy-script"}}` + pageText("copy.js") + `{{end}}` + pageText("pages.html")))

func completionHeaders(w http.ResponseWriter) {
	ownedHeaders(w)
	// Authorize only the embedded clipboard script. User-provided command text
	// remains escaped HTML and is read as textContent, never executed as script.
	sum := sha256.Sum256([]byte(pageText("copy.js")))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}
