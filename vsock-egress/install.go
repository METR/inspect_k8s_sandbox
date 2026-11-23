package main

import (
	"embed"
	"errors"
	"flag"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

//go:embed profiles/amd64/vsock-egress-launcher.json profiles/amd64/vsock-egress.json
//go:embed profiles/arm64/vsock-egress-launcher.json profiles/arm64/vsock-egress.json
var profiles embed.FS

// install writes this build's two seccomp profiles into profiles/ of the kubelet's seccomp directory, so the image that installs them needs no shell.
func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: vsock-egress install <the kubelet's seccomp directory>")
	}
	to := filepath.Join(fs.Arg(0), "profiles")
	if err := os.MkdirAll(to, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"vsock-egress-launcher.json", "vsock-egress.json"} {
		profile, err := profiles.ReadFile(path.Join("profiles", runtime.GOARCH, name))
		if err != nil {
			return err
		}
		// Made anew beside its place, then renamed: the runtime never reads half a profile, and nothing left there is written through.
		beside := filepath.Join(to, "."+name)
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
		if err := os.Rename(beside, filepath.Join(to, name)); err != nil {
			return err
		}
	}
	return nil
}
