package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestInstallReplacesEachProfileWhole(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0)) // no mask: the modes are the ones install asks for
	dir := filepath.Join(t.TempDir(), "profiles")
	place := filepath.Join(dir, "vsock-egress.json")
	// A node's first install makes the directory; the next finds an older profile there, and a link to it under the copy's name.
	if err := install([]string{filepath.Dir(dir)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(place, []byte("an older profile"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(place, filepath.Join(dir, ".vsock-egress.json")); err != nil {
		t.Fatal(err)
	}
	older, err := os.Stat(place)
	if err != nil {
		t.Fatal(err)
	}

	if err := install([]string{filepath.Dir(dir)}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"vsock-egress-launcher.json", "vsock-egress.json"} {
		want, err := os.ReadFile(filepath.Join("profiles", runtime.GOARCH, name))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s holds %d bytes, %v: want this architecture's %d", name, len(got), err, len(want))
		}
	}
	newer, err := os.Stat(place)
	if err != nil || os.SameFile(older, newer) {
		t.Fatalf("the older profile was written over in place (%v): the runtime could read half a profile", err)
	}
	made, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if made.Mode().Perm() != 0o755 || newer.Mode().Perm() != 0o644 {
		t.Fatalf("the directory's mode is %v and the profile's %v: want 0755 and 0644, as mkdir and cp gave them", made.Mode(), newer.Mode())
	}
}

func TestInstallFailsWhereAProfileCannotTakeItsPlace(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "profiles", "vsock-egress.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(os.Args[0], "install", dir).CombinedOutput()

	if err == nil || !strings.Contains(string(out), "install_failed: ") {
		t.Fatalf("got %v and %q: want install_failed with a directory where a profile goes, or the node would be taken to hold it", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "profiles", ".vsock-egress.json")); err != nil {
		t.Fatalf("%v: the copy left beside the profile's place has the one name the README tells an operator to admit for no container", err)
	}
}

func TestInstallFailsWhereAProfileIsCutShort(t *testing.T) {
	dir := t.TempDir()
	short := exec.Command(os.Args[0], "install", dir)
	short.Env = append(os.Environ(), fullDisk+"=4096") // less than either profile

	out, err := short.CombinedOutput()

	if _, placed := os.Stat(filepath.Join(dir, "profiles", "vsock-egress-launcher.json")); err == nil || placed == nil {
		t.Fatalf("install gave %v and %q, and a profile cut short in its place gave %v: the runtime refuses it, and with it every pod that names it", err, out, placed)
	}
}
