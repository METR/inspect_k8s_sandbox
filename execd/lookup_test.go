// Not with cgo: there libc looks the user up, and what its failure says depends on the host's name services.

//go:build !cgo

package main

import (
	"strings"
	"syscall"
	"testing"
)

// Regression: with no descriptor to open /etc/passwd with, a lookup said "unknown user", which a client takes for a user the container lacks.
func TestALookupThatFailsIsNotAnUnknownUser(t *testing.T) {
	var was syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &was)
	for _, name := range []string{"nobody2", "4242424"} {
		_, _, _, missing := lookupUser(name)
		nofile(syscall.Rlimit{Cur: 0, Max: was.Max})
		_, _, _, failed := lookupUser(name)
		nofile(was)

		if missing == nil || missing.Error() != "unknown user "+name {
			t.Fatalf("with no entry, %s got %v, want unknown user", name, missing)
		}
		if failed == nil || !strings.HasPrefix(failed.Error(), "cannot look up user "+name+": ") {
			t.Fatalf("with no descriptor left, %s got %v, want the lookup's failure", name, failed)
		}
	}
}
