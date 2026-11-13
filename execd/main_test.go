package main

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// An image or pod that set the marker made the first exec the daemon: it printed no fingerprint and never returned.
func TestTheFirstExecPrintsItsDaemonsFingerprintWhenItInheritsTheMarker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // only bounds a hang
	defer cancel()
	first := exec.CommandContext(ctx, os.Args[0], "listen", "--key-sha256", strings.Repeat("00", 32)) // on any free port
	first.Env = append(os.Environ(), foregroundEnv+"=1")
	t.Cleanup(stopOthers) // the daemon it leaves running

	out, _ := first.Output() // its exit status may go to another test's reaper

	if !regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(out) {
		t.Fatalf("the first exec printed %q, want its daemon's fingerprint", out)
	}
}
