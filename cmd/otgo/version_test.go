package main

import (
	"bytes"
	"context"
	"errors"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/darron/go-opentunnel"
)

func TestVersionCommand(t *testing.T) {
	for _, command := range []string{"version", "--version"} {
		t.Run(command, func(t *testing.T) {
			var out, errout bytes.Buffer
			if err := run(context.Background(), []string{command}, strings.NewReader(""), &out, &errout); err != nil {
				t.Fatal(err)
			}
			fields := strings.Fields(out.String())
			if len(fields) != 4 || fields[0] != "otgo" || fields[1] != opentunnel.Version || !strings.HasPrefix(fields[2], "sha=") || errout.Len() != 0 {
				t.Fatalf("version output = %q, stderr = %q", out.String(), errout.String())
			}
			out.Reset()
			if err := run(context.Background(), []string{command, "unexpected"}, strings.NewReader(""), &out, &errout); err == nil || out.Len() != 0 {
				t.Fatalf("unexpected version argument accepted: %v, output %q", err, out.String())
			}
			writeErr := errors.New("version output failed")
			if err := run(context.Background(), []string{command}, strings.NewReader(""), failingWriter{err: writeErr}, &errout); !errors.Is(err, writeErr) {
				t.Fatalf("output failure not returned: %v", err)
			}
		})
	}
}

func TestBuildMetadata(t *testing.T) {
	sha := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	for _, test := range []struct {
		name      string
		settings  []debug.BuildSetting
		revision  string
		state     string
		wantSHA   string
		wantState string
	}{
		{name: "clean", settings: []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "false"}}, wantSHA: sha, wantState: "clean"},
		{name: "dirty", settings: []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "true"}}, wantSHA: sha, wantState: "dirty"},
		{name: "archive", revision: sha, state: "clean", wantSHA: sha, wantState: "clean"},
		{name: "vcs wins", settings: []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "true"}}, revision: other, state: "clean", wantSHA: sha, wantState: "dirty"},
		{name: "no metadata", wantSHA: "unknown", wantState: "unknown"},
		{name: "unknown state", revision: sha, wantSHA: sha, wantState: "unknown"},
		{name: "invalid revision", revision: "injected\ntext", state: "clean", wantSHA: "unknown", wantState: "unknown"},
		{name: "invalid state", revision: sha, state: "not-clean\n", wantSHA: sha, wantState: "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := &debug.BuildInfo{Settings: test.settings}
			gotSHA, gotState := buildMetadata(info, test.revision, test.state)
			if gotSHA != test.wantSHA || gotState != test.wantState {
				t.Fatalf("metadata = %q, %q; want %q, %q", gotSHA, gotState, test.wantSHA, test.wantState)
			}
		})
	}
	if sha, state := buildMetadata(nil, "", ""); sha != "unknown" || state != "unknown" {
		t.Fatalf("missing build info = %q, %q", sha, state)
	}
}
