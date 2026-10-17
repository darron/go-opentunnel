package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/darron/go-opentunnel/internal/authproxy"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

func qrTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	return ok && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(f.Fd()))
}

func writeProxyAnnouncement(out io.Writer, jsonOutput bool, profile string, cfg authproxy.Config, mode string, terminal bool) error {
	// Machine output stays JSON even when --qr=always was explicitly requested.
	if jsonOutput {
		return json.NewEncoder(out).Encode(struct{ Type, Profile, Hostname, Upstream, Mode string }{"proxy", profile, cfg.Binding.Hostname, cfg.Upstream, cfg.Mode})
	}
	if _, err := fmt.Fprintf(out, "protected https://%s -> %s (profile=%s, auth=%s)\n", terminalText(cfg.Binding.Hostname), terminalText(cfg.Upstream), profile, cfg.Mode); err != nil {
		return err
	}
	if mode == "never" || mode == "auto" && !terminal {
		return nil
	}
	code, err := qrcode.New("https://"+cfg.Binding.Hostname+"/", qrcode.Medium)
	if err != nil {
		return err
	}
	bitmap := code.Bitmap() // Includes the encoder's four-module quiet zone.
	var text strings.Builder
	text.WriteString("Scan to open on your phone:\n")
	for y := 0; y < len(bitmap); y += 2 {
		// Explicit black-on-white colors remain scannable on a dark terminal.
		text.WriteString("\x1b[30;107m")
		for x, upper := range bitmap[y] {
			lower := y+1 < len(bitmap) && bitmap[y+1][x]
			switch {
			case upper && lower:
				text.WriteRune('█')
			case upper:
				text.WriteRune('▀')
			case lower:
				text.WriteRune('▄')
			default:
				text.WriteByte(' ')
			}
		}
		text.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(out, text.String())
	return err
}
