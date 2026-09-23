package confine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

const goodPolicy = `
version: "1"
workloads:
  - id: agent-eval-01
    allow:
      - host: pypi.org
        ports: [443]
        note: package index
      - host: "*.pythonhosted.org"
        ports: [443]
      - host: api.github.com
        ports: [443]
`

func TestPolicyPermitsOnlyWhatItLists(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, goodPolicy))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	allowed := []struct {
		host string
		port int
	}{
		{"pypi.org", 443},
		{"files.pythonhosted.org", 443},
		{"a.b.pythonhosted.org", 443},
		{"api.github.com", 443},
		{"PyPI.org", 443},  // case-insensitive
		{"pypi.org.", 443}, // trailing dot is the same name
	}
	for _, tc := range allowed {
		if _, err := p.Permits("agent-eval-01", tc.host, tc.port); err != nil {
			t.Errorf("%s:%d should be permitted: %v", tc.host, tc.port, err)
		}
	}

	denied := []struct {
		host string
		port int
		why  string
	}{
		{"pypi.org", 80, "wrong port"},
		{"evil.com", 443, "not listed"},
		{"pythonhosted.org", 443, "apex is not covered by *.pythonhosted.org"},
		{"evilpythonhosted.org", 443, "near-miss must not match the wildcard"},
		{"notapi.github.com", 443, "exact rule must not match a longer name"},
		{"api.github.com.evil.com", 443, "suffix attack"},
		{"140.82.121.4", 443, "IP literal not listed"},
	}
	for _, tc := range denied {
		if _, err := p.Permits("agent-eval-01", tc.host, tc.port); err == nil {
			t.Errorf("%s:%d should be denied (%s)", tc.host, tc.port, tc.why)
		}
	}
}

func TestUnknownWorkloadGetsNothing(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, goodPolicy))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	_, err = p.Permits("agent-nobody-registered-this", "pypi.org", 443)
	if err == nil {
		t.Fatal("an unregistered workload was permitted")
	}
	if !errors.Is(err, ErrNotPermitted) {
		t.Errorf("got %v, want ErrNotPermitted", err)
	}
}

func TestPolicyRejectsBroadGrants(t *testing.T) {
	bad := map[string]string{
		"wildcard workload": `
version: "1"
workloads:
  - id: "*"
    allow: [{host: pypi.org}]
`,
		"wildcard host": `
version: "1"
workloads:
  - id: a
    allow: [{host: "*"}]
`,
		"bare tld wildcard": `
version: "1"
workloads:
  - id: a
    allow: [{host: "*.com"}]
`,
		"interior wildcard": `
version: "1"
workloads:
  - id: a
    allow: [{host: "api.*.com"}]
`,
		"duplicate workload": `
version: "1"
workloads:
  - id: a
    allow: [{host: pypi.org}]
  - id: a
    allow: [{host: evil.com}]
`,
		"wrong version": `
version: "2"
workloads:
  - id: a
    allow: [{host: pypi.org}]
`,
		"no workloads": `
version: "1"
workloads: []
`,
		"bad port": `
version: "1"
workloads:
  - id: a
    allow: [{host: pypi.org, ports: [70000]}]
`,
	}

	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicy(writePolicy(t, body)); err == nil {
				t.Error("policy was accepted")
			}
		})
	}
}

func TestEmptyPortsMeansAnyPort(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, `
version: "1"
workloads:
  - id: a
    allow:
      - host: internal.example.com
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, port := range []int{80, 443, 8080} {
		if _, err := p.Permits("a", "internal.example.com", port); err != nil {
			t.Errorf("port %d should be permitted when ports is empty: %v", port, err)
		}
	}
}

func TestNoteIsCarriedBack(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, goodPolicy))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	note, err := p.Permits("agent-eval-01", "pypi.org", 443)
	if err != nil {
		t.Fatalf("permits: %v", err)
	}
	if note != "package index" {
		t.Errorf("note = %q, want %q", note, "package index")
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		defPort  int
		wantHost string
		wantPort int
	}{
		{"pypi.org:443", 0, "pypi.org", 443},
		{"pypi.org", 443, "pypi.org", 443},
		{"PyPI.org:8080", 0, "pypi.org", 8080},
		{"[2606:4700::1111]:443", 0, "2606:4700::1111", 443},
	}
	for _, tc := range tests {
		host, port, err := SplitHostPort(tc.in, tc.defPort)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("%s -> %s:%d, want %s:%d", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}
