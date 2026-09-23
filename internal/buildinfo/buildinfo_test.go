package buildinfo

import "testing"

func TestModuleVersion(t *testing.T) {
	cases := []struct{ stamped, recorded, want string }{
		{"v0.2.0", "v0.1.0", "v0.2.0"}, // a release build's stamp wins
		{"dev", "v0.1.0", "v0.1.0"},    // go install github.com/.../cmd/agw@v0.1.0
		{"dev", "(devel)", "dev"},      // go build in a clone
		{"dev", "", "dev"},
	}
	for _, c := range cases {
		if got := moduleVersion(c.stamped, c.recorded); got != c.want {
			t.Errorf("moduleVersion(%q, %q) = %q, want %q", c.stamped, c.recorded, got, c.want)
		}
	}
}
