package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/term"
	"image"
	"image/color"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/darron/go-opentunnel/internal/authproxy"
	"github.com/makiuchi-d/gozxing"
	zxingqr "github.com/makiuchi-d/gozxing/qrcode"
)

func TestProxyAnnouncementQRCodeDecodesPublicURL(t *testing.T) {
	cfg := authproxy.Config{Binding: authproxy.Binding{Hostname: "inbox.opentunnel.xyz"}, Upstream: "http://127.0.0.1:57732", Mode: "github"}
	for _, tc := range []struct {
		mode               string
		terminal, json, qr bool
	}{{"auto", true, false, true}, {"auto", false, false, false}, {"always", false, false, true}, {"never", true, false, false}, {"always", true, true, false}, {"auto", true, true, false}} {
		t.Run(fmt.Sprintf("%s/terminal=%v/json=%v", tc.mode, tc.terminal, tc.json), func(t *testing.T) {
			var out bytes.Buffer
			if err := writeProxyAnnouncement(&out, tc.json, "inbox", cfg, tc.mode, tc.terminal); err != nil {
				t.Fatal(err)
			}
			if tc.json {
				var value map[string]any
				if err := json.Unmarshal(out.Bytes(), &value); err != nil {
					t.Fatal(err)
				}
			}
			hasQR := strings.Contains(out.String(), "\x1b[")
			if hasQR != tc.qr {
				t.Fatalf("QR present=%v wanted %v", hasQR, tc.qr)
			}
			if !tc.qr {
				return
			}
			// Decode pixels reconstructed from terminal glyphs with a different QR
			// implementation. This tests the rendered result, including polarity/border.
			var rows [][]bool
			for _, line := range strings.Split(out.String(), "\n") {
				if !strings.HasPrefix(line, "\x1b[30;107m") {
					continue
				}
				line = strings.TrimSuffix(strings.TrimPrefix(line, "\x1b[30;107m"), "\x1b[0m")
				var upper, lower []bool
				for _, r := range line {
					switch r {
					case ' ':
						upper = append(upper, false)
						lower = append(lower, false)
					case '█':
						upper = append(upper, true)
						lower = append(lower, true)
					case '▀':
						upper = append(upper, true)
						lower = append(lower, false)
					case '▄':
						upper = append(upper, false)
						lower = append(lower, true)
					default:
						t.Fatalf("unexpected glyph %q", r)
					}
				}
				rows = append(rows, upper, lower)
			}
			const scale = 5
			img := image.NewGray(image.Rect(0, 0, len(rows[0])*scale, len(rows)*scale))
			for y, row := range rows {
				for x, black := range row {
					v := color.Gray{Y: 255}
					if black {
						v.Y = 0
					}
					for dy := range scale {
						for dx := range scale {
							img.SetGray(x*scale+dx, y*scale+dy, v)
						}
					}
				}
			}
			bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := zxingqr.NewQRCodeReader().DecodeWithoutHints(bitmap)
			if err != nil {
				t.Fatal(err)
			}
			if got := decoded.GetText(); got != "https://inbox.opentunnel.xyz/" {
				t.Fatalf("decoded %q", got)
			}
		})
	}
}

type qrFailWriter struct{}

func (qrFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestQRValidationAndWriteFailure(t *testing.T) {
	var out bytes.Buffer
	err := run(t.Context(), []string{"proxy", "--qr=wrong"}, strings.NewReader(""), &out, &out)
	if err == nil || !strings.Contains(err.Error(), "qr must be auto, always or never") {
		t.Fatalf("validation: %v", err)
	}
	if err := writeProxyAnnouncement(qrFailWriter{}, false, "inbox", authproxy.Config{}, "always", true); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write: %v", err)
	}
}

func TestQRAutoRequiresActualTerminal(t *testing.T) {
	var buffer bytes.Buffer
	if qrTerminal(&buffer) {
		t.Fatal("buffer recognized as terminal")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	if qrTerminal(writer) {
		t.Fatal("pipe recognized as terminal")
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	if qrTerminal(null) {
		t.Fatal("character device recognized as terminal")
	}
}

// Run the compiled test binary under a PTY to exercise automatic detection.
// The usual go test runner pipes output, so it cannot cover this branch.
func TestQRInteractiveTerminal(t *testing.T) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Skip("requires a real terminal or PTY")
	}
	t.Setenv("TERM", "xterm-256color")
	if !qrTerminal(os.Stdout) {
		t.Fatal("TTY not recognized")
	}
	var out bytes.Buffer
	cfg := authproxy.Config{Binding: authproxy.Binding{Hostname: "phone.opentunnel.xyz"}}
	if err := writeProxyAnnouncement(&out, false, "phone", cfg, "auto", qrTerminal(os.Stdout)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Scan to open on your phone:") {
		t.Fatal("automatic QR missing on TTY")
	}
	t.Setenv("TERM", "dumb")
	if qrTerminal(os.Stdout) {
		t.Fatal("dumb terminal enables automatic QR")
	}
}
