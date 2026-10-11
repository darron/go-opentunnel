package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"github.com/darron/go-opentunnel"
)

// Release archive builds supply these with -ldflags because archives omit .git.
// Go's recorded VCS metadata takes precedence when it is present.
var buildRevision, buildState string

func printVersion(out io.Writer) error {
	info, _ := debug.ReadBuildInfo()
	revision, state := buildMetadata(info, buildRevision, buildState)
	_, err := fmt.Fprintf(out, "otgo %s sha=%s %s\n", opentunnel.Version, revision, state)
	return err
}

func buildMetadata(info *debug.BuildInfo, revision, state string) (string, string) {
	if info != nil {
		var vcs, recordedRevision, modified string
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs":
				vcs = setting.Value
			case "vcs.revision":
				recordedRevision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
		if vcs == "git" && recordedRevision != "" {
			revision, state = recordedRevision, "unknown"
			switch modified {
			case "false":
				state = "clean"
			case "true":
				state = "dirty"
			}
		}
	}
	if len(revision) != 40 && len(revision) != 64 {
		return "unknown", "unknown"
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return "unknown", "unknown"
	}
	if state != "clean" && state != "dirty" {
		state = "unknown"
	}
	return strings.ToLower(revision), state
}
