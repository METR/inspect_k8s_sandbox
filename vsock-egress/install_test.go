package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallReplacesEachProfileWholeAndLeavesNothingElse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles")
	place := filepath.Join(dir, "vsock-egress.json")
	// A node's first install makes the directory; the next finds an older profile there.
	if err := install([]string{filepath.Dir(dir)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(place, []byte("an older profile"), 0o644); err != nil {
		t.Fatal(err)
	}
	older, err := os.Stat(place)
	if err != nil {
		t.Fatal(err)
	}

	if err := install([]string{filepath.Dir(dir)}); err != nil {
		t.Fatal(err)
	}

	names := []string{"vsock-egress-launcher.json", "vsock-egress.json"}
	for _, name := range names {
		want, err := os.ReadFile(filepath.Join("profiles", runtime.GOARCH, name))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s holds %d bytes, %v: want this architecture's %d", name, len(got), err, len(want))
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != len(names) {
		t.Fatalf("the directory holds %v, %v: want the two profiles alone", entries, err)
	}
	if newer, err := os.Stat(place); err != nil || os.SameFile(older, newer) {
		t.Fatalf("the older profile was written over in place (%v): the runtime could read half a profile", err)
	}
}

func TestInstallFailsWhereAProfileCannotTakeItsPlace(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "profiles", "vsock-egress.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := install([]string{dir}); err == nil {
		t.Fatal("install passed with a directory where a profile goes: the node would be taken to hold it")
	}
}
