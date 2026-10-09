// otgo is a small diagnostic consumer of the opentunnel package.
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

// run is separated from main so command parsing and cancellation are testable.
func run(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) error {
	return runCommand(ctx, args, in, out, errout)
}
