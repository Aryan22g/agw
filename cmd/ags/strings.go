package main

import (
	"strings"
)

func splitLines(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(v, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func cutHeader(line string) (name, value string, ok bool) {
	name, value, ok = strings.Cut(line, ":")
	return strings.TrimSpace(name), strings.TrimSpace(value), ok
}
