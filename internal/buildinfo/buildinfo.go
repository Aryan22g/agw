// Package buildinfo reports which build of the software is running.
//
// Evidence is only as useful as the ability to say which code produced it, so
// every binary answers `version` the same way. Release builds stamp Version
// through -ldflags. Anything else falls back to what the Go toolchain embeds:
// `go install ...@v0.1.0` records the module version, and a build from a clone
// records the commit.
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
	version, commit, date, dirty := Version, Commit, Date, false
	if bi, ok := debug.ReadBuildInfo(); ok {
		version = moduleVersion(version, bi.Main.Version)
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
	out := fmt.Sprintf("%s %s (commit %s", prog, version, commit)
	if date != "" {
		out += ", built " + date
	}
	return out + fmt.Sprintf(", %s, %s/%s)", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// moduleVersion prefers a version stamped at link time, then the module
// version the toolchain recorded. "(devel)" is what a build from a clone
// records, which says nothing.
func moduleVersion(stamped, recorded string) string {
	if stamped != "dev" || recorded == "" || recorded == "(devel)" {
		return stamped
	}
	return recorded
}
