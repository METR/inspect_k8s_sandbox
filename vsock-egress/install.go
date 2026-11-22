package main

import (
	"embed"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

//go:embed profiles
var profiles embed.FS

// install writes this build's two seccomp profiles into profiles/ of the kubelet's seccomp directory, so the image that installs them needs no shell.
func install(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: vsock-egress install <the kubelet's seccomp directory>")
	}
	from, to := path.Join("profiles", runtime.GOARCH), filepath.Join(args[0], "profiles")
	entries, err := profiles.ReadDir(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(to, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		profile, err := profiles.ReadFile(path.Join(from, entry.Name()))
		if err != nil {
			return err
		}
		// Made anew beside its place, then renamed: the runtime never reads half a profile, and nothing left there is written through.
		beside := filepath.Join(to, "."+entry.Name())
		if err := os.Remove(beside); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		file, err := os.OpenFile(beside, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = file.Write(profile)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
		if err := os.Rename(beside, filepath.Join(to, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
