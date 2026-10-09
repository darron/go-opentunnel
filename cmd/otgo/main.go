// otgo exercises the public opentunnel package for testing and diagnostics.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "otgo:", err)
		if !errors.Is(err, context.Canceled) {
			return 1
		}
	}
	return 0
}

// run keeps command parsing and cancellation testable without process exit.
func run(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) error {
	return runCommand(ctx, args, in, out, errout)
}
