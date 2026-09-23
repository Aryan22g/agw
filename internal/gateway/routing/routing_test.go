package routing_test

import (
	"errors"
	"testing"

	"github.com/Aryan22g/agw/internal/gateway/routing"
)

func registry(t *testing.T) *routing.Registry {
	t.Helper()
	reg, err := routing.NewRegistry([]routing.Route{
		{ID: "issue_create", Method: "POST",
			PathPattern: "/v1/tools/github/repos/{owner}/{repo}/issues",
			Action:      "github.issue.create", ResourceType: "github_repo",
			ResourceIDTemplate: "{owner}/{repo}", BackendID: "github", RiskClass: routing.RiskWrite},
		{ID: "issue_list", Method: "GET",
			PathPattern: "/v1/tools/github/repos/{owner}/{repo}/issues",
			Action:      "github.issue.list", ResourceType: "github_repo",
			ResourceIDTemplate: "{owner}/{repo}", BackendID: "github", RiskClass: routing.RiskRead},
		{ID: "repo_delete", Method: "DELETE",
			PathPattern: "/v1/tools/github/repos/{owner}/{repo}",
			Action:      "github.repo.delete", ResourceType: "github_repo",
			ResourceIDTemplate: "{owner}/{repo}", BackendID: "github", RiskClass: routing.RiskDestructive},
	})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return reg
}

func TestMatchesExtractsActionAndResource(t *testing.T) {
	reg := registry(t)

	m, err := reg.Match("POST", "/v1/tools/github/repos/acme/app/issues")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if m.Action != "github.issue.create" {
		t.Errorf("action = %q", m.Action)
	}
	if m.ResourceID != "acme/app" {
		t.Errorf("resource = %q, want acme/app", m.ResourceID)
	}
	if m.Route.RiskClass != routing.RiskWrite {
		t.Errorf("risk = %q, want write", m.Route.RiskClass)
	}
}

// TestMethodIsPartOfTheRoute: the same path under a different method must
// resolve to a different action, or a read grant would authorize a write.
func TestMethodIsPartOfTheRoute(t *testing.T) {
	reg := registry(t)

	get, err := reg.Match("GET", "/v1/tools/github/repos/acme/app/issues")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	post, err := reg.Match("POST", "/v1/tools/github/repos/acme/app/issues")
	if err != nil {
		t.Fatalf("POST: %v", err)
	}

	if get.Action == post.Action {
		t.Fatalf("GET and POST resolved to the same action %q", get.Action)
	}
	if get.Route.RiskClass == post.Route.RiskClass {
		t.Errorf("GET and POST share risk class %q", get.Route.RiskClass)
	}
}

// TestRouteConfusionRejected is the security property: a path that does not
// exactly match a pattern must NOT resolve, because resolving it to the wrong
// route means authorizing the wrong action on the wrong resource.
func TestRouteConfusionRejected(t *testing.T) {
	reg := registry(t)

	paths := []string{
		"/v1/tools/github/repos/acme/app/issues/extra",    // deeper than the pattern
		"/v1/tools/github/repos/acme/issues",              // one segment short
		"/v1/tools/github/repos/acme/app/issues/",         // trailing slash
		"/V1/TOOLS/GITHUB/REPOS/acme/app/issues",          // case differs
		"//v1/tools/github/repos/acme/app/issues",         // doubled leading slash
		"/v1/tools/github/repos//app/issues",              // empty path variable
		"/v1/tools/github/repos/acme/app/issues/../admin", // traversal-shaped
		"/v1/tools/github/repos/acme/app/ISSUES",          // literal segment case
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if m, err := reg.Match("POST", path); err == nil {
				t.Errorf("path resolved to action %q resource %q; it should not match",
					m.Action, m.ResourceID)
			}
		})
	}
}

// TestPathVariableCannotSpanSegments: a variable matches one segment, so an
// attacker cannot smuggle extra path structure into a resource id.
func TestPathVariableCannotSpanSegments(t *testing.T) {
	reg := registry(t)

	if m, err := reg.Match("DELETE", "/v1/tools/github/repos/acme/app/extra"); err == nil {
		t.Errorf("a path variable spanned a '/' and produced resource %q", m.ResourceID)
	}
}

// TestEncodedSlashDoesNotSplitSegments: %2F must stay inside one variable
// rather than being treated as a separator.
func TestEncodedSlashDoesNotSplitSegments(t *testing.T) {
	reg := registry(t)

	m, err := reg.Match("DELETE", "/v1/tools/github/repos/acme/my%2Frepo")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if m.ResourceID != "acme/my%2Frepo" {
		t.Errorf("resource = %q; the encoded slash must stay within the variable", m.ResourceID)
	}
}

func TestUnknownRouteReturnsSentinel(t *testing.T) {
	reg := registry(t)

	_, err := reg.Match("POST", "/v1/tools/github/admin/shutdown")
	if !errors.Is(err, routing.ErrRouteNotFound) {
		t.Errorf("got %v, want ErrRouteNotFound", err)
	}
}

func TestInvalidRoutesRejectedAtLoad(t *testing.T) {
	cases := map[string]routing.Route{
		"no id":            {Method: "GET", PathPattern: "/a", Action: "a", ResourceType: "t", ResourceIDTemplate: "x", BackendID: "b", RiskClass: routing.RiskRead},
		"no method":        {ID: "r", PathPattern: "/a", Action: "a", ResourceType: "t", ResourceIDTemplate: "x", BackendID: "b", RiskClass: routing.RiskRead},
		"no action":        {ID: "r", Method: "GET", PathPattern: "/a", ResourceType: "t", ResourceIDTemplate: "x", BackendID: "b", RiskClass: routing.RiskRead},
		"no backend":       {ID: "r", Method: "GET", PathPattern: "/a", Action: "a", ResourceType: "t", ResourceIDTemplate: "x", RiskClass: routing.RiskRead},
		"bad risk":         {ID: "r", Method: "GET", PathPattern: "/a", Action: "a", ResourceType: "t", ResourceIDTemplate: "x", BackendID: "b", RiskClass: "catastrophic"},
		"relative pattern": {ID: "r", Method: "GET", PathPattern: "a", Action: "a", ResourceType: "t", ResourceIDTemplate: "x", BackendID: "b", RiskClass: routing.RiskRead},
	}

	for name, route := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := routing.NewRegistry([]routing.Route{route}); err == nil {
				t.Error("an invalid route was accepted at load time")
			}
		})
	}
}

// TestTemplateMustResolveFully: a resource id template referencing a variable
// the pattern does not define would otherwise produce a literal "{owner}" as a
// resource id, which policy would then match against by accident.
func TestTemplateMustResolveFully(t *testing.T) {
	_, err := routing.NewRegistry([]routing.Route{{
		ID: "r", Method: "GET", PathPattern: "/v1/{repo}",
		Action: "a", ResourceType: "t",
		ResourceIDTemplate: "{owner}/{repo}", // owner is never bound
		BackendID:          "b", RiskClass: routing.RiskRead,
	}})
	if err != nil {
		return // rejected at load, which is ideal
	}

	reg, _ := routing.NewRegistry([]routing.Route{{
		ID: "r", Method: "GET", PathPattern: "/v1/{repo}",
		Action: "a", ResourceType: "t", ResourceIDTemplate: "{owner}/{repo}",
		BackendID: "b", RiskClass: routing.RiskRead,
	}})
	if m, err := reg.Match("GET", "/v1/app"); err == nil {
		t.Errorf("unresolved template produced resource %q instead of failing", m.ResourceID)
	}
}

func TestValidateBackendsCatchesMissing(t *testing.T) {
	reg := registry(t)

	if err := reg.ValidateBackends(map[string]struct{}{"github": {}}); err != nil {
		t.Errorf("configured backend reported missing: %v", err)
	}

	err := reg.ValidateBackends(map[string]struct{}{"something-else": {}})
	if err == nil {
		t.Fatal("a route referencing an unconfigured backend was accepted")
	}
}
