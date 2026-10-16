package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/darron/go-opentunnel"
)

// Only a verified durable pending record justifies advertising resumability.
func pendingProvisionError(client *opentunnel.Client, common commonFlags, err error, errout io.Writer) error {
	if !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pending, loadErr := client.Pending(ctx, common.profile)
	if loadErr != nil || pending == nil {
		return err
	}
	args := []string{"otgo", "resume", "--profile", common.profile}
	if common.api != "" {
		args = append(args, "--api", common.api)
	}
	if common.dataDir != "" {
		path, e := filepath.Abs(common.dataDir)
		if e != nil {
			return err
		}
		args = append(args, "--data-dir", path)
	}
	caCertFile, caErr := common.effectiveCACert("")
	if caErr != nil {
		return err
	}
	if caCertFile != "" || common.caCertExplicit {
		args = append(args, "--ca-cert", caCertFile)
	}
	_, writeErr := fmt.Fprintln(errout, "Provisioning timed out; the stored pending request remains resumable. Run:", shellCommand(args))
	return errors.Join(err, writeErr)
}
func shellCommand(args []string) string {
	quoted := make([]string, len(args))
	for i, s := range args {
		quoted[i] = s
		if s == "" || strings.IndexFunc(s, func(r rune) bool {
			safe := (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./:@%+=,-", r))
			return !safe
		}) >= 0 {
			quoted[i] = "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
		}
	}
	return strings.Join(quoted, " ")
}
