package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// Progress uses stderr; redirected output gets one line per step, not animation.
type authProgress struct {
	mu      sync.Mutex
	out     io.Writer
	animate bool
	message string
	frame   int
	err     error
	done    chan struct{}
	joined  chan struct{}
	once    sync.Once
}

func terminalProgress(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
func newAuthProgress(out io.Writer, enabled, animate bool) *authProgress {
	if !enabled {
		out = io.Discard
		animate = false
	}
	p := &authProgress{out: out, animate: animate, done: make(chan struct{}), joined: make(chan struct{})}
	if !animate {
		close(p.joined)
		return p
	}
	go func() {
		defer close(p.joined)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-ticker.C:
				p.mu.Lock()
				if p.message != "" {
					p.frame++
					p.render()
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}
func (p *authProgress) render() {
	if p.err != nil {
		return
	}
	if p.animate {
		_, p.err = fmt.Fprintf(p.out, "\r\x1b[2K%c %s", "|/-\\"[p.frame%4], p.message)
	} else {
		_, p.err = fmt.Fprintf(p.out, "... %s\n", p.message)
	}
}
func (p *authProgress) step(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.message = message
	p.render()
}
func (p *authProgress) stop() error {
	p.once.Do(func() {
		close(p.done)
		<-p.joined
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.animate && p.message != "" && p.err == nil {
			_, p.err = io.WriteString(p.out, "\n")
		}
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func browserCommand(platform, address string) (string, []string, error) {
	switch platform {
	case "darwin":
		return "open", []string{address}, nil
	case "linux":
		return "xdg-open", []string{address}, nil
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", address}, nil
	default:
		return "", nil, errors.New("browser launch is unavailable")
	}
}
func openBrowser(ctx context.Context, address string) error {
	command, args, err := browserCommand(runtime.GOOS, address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// No shell, and no subprocess output: launcher errors can contain the setup token.
	if err := exec.CommandContext(ctx, command, args...).Run(); err != nil { // #nosec G204 -- Fixed OS launcher; the local setup URL is a separate argument.
		return errors.New("could not open the default browser")
	}
	return nil
}
