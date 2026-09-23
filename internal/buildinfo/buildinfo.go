// Package buildinfo reports which build of the software is running.
//
// Evidence is only as useful as the ability to say which code produced it, so
// every binary answers `version` the same way. Release builds stamp Version
// through -ldflags; anything else falls back to the VCS data the Go toolchain
// embeds, so even a `go install` build can say which commit it came from.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at link time by release builds:
//
//	-ldflags "-X github.com/Aryan22g/agw/internal/buildinfo.Version=v0.9.0
//	          -X github.com/Aryan22g/agw/internal/buildinfo.Commit=abc123
//	          -X github.com/Aryan22g/agw/internal/buildinfo.Date=2026-09-23T00:00:00Z"
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String renders one line suitable for `<prog> version`.
func String(prog string) string {
	commit, date, dirty := Commit, Date, false
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.time":
				if date == "" {
					date = s.Value
				}
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	if dirty {
		commit += "-dirty"
	}
	out := fmt.Sprintf("%s %s (commit %s", prog, Version, commit)
	if date != "" {
		out += ", built " + date
	}
	return out + fmt.Sprintf(", %s, %s/%s)", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
