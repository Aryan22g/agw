package routing

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type Registry struct {
	routes []compiledRoute
}

func NewRegistry(routes []Route) (*Registry, error) {
	compiled := make([]compiledRoute, 0, len(routes))

	for _, r := range routes {
		if err := validateRoute(r); err != nil {
			return nil, err
		}

		re, vars, err := compilePathPattern(r.PathPattern)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", r.ID, err)
		}

		compiled = append(compiled, compiledRoute{
			route: r,
			re:    re,
			vars:  vars,
		})
	}

	return &Registry{routes: compiled}, nil
}

func (r *Registry) Match(method string, path string) (*MatchResult, error) {
	if r == nil {
		return nil, ErrRouteNotFound
	}

	method = strings.ToUpper(strings.TrimSpace(method))

	for _, cr := range r.routes {
		if method != strings.ToUpper(cr.route.Method) {
			continue
		}

		pathVars, ok := extractVars(cr.re, cr.vars, path)
		if !ok {
			continue
		}

		resourceID, err := renderTemplate(cr.route.ResourceIDTemplate, pathVars)
		if err != nil {
			return nil, err
		}

		return &MatchResult{
			Route:        cr.route,
			PathVars:     pathVars,
			Action:       cr.route.Action,
			ResourceType: cr.route.ResourceType,
			ResourceID:   resourceID,
			BackendID:    cr.route.BackendID,
		}, nil
	}

	return nil, ErrRouteNotFound
}

func (r *Registry) MustMatch(method string, path string) *MatchResult {
	m, err := r.Match(method, path)
	if err != nil {
		panic(err)
	}
	return m
}

// Optional helper if you want to map unknown route to HTTP semantics.
func IsRouteNotFound(err error) bool {
	return err == ErrRouteNotFound
}

func StatusCodeForMatchError(err error) int {
	if err == ErrRouteNotFound {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// usage example:
// reg, err := routing.LoadRegistry("configs/gateway/routes.yaml")
// if err != nil {
// 	panic(err)
// }

// match, err := reg.Match("POST", "/v1/tools/github/repos/acme/app/issues")
// if err != nil {
// 	panic(err)
// }

// fmt.Println(match.Action)      // github.issue.create
// fmt.Println(match.ResourceID)  // acme/app
// fmt.Println(match.BackendID)   // github_connector
// fmt.Println(match.Route.RiskClass) // write

// BackendIDs returns the distinct backend ids every route refers to.
func (r *Registry) BackendIDs() []string {
	if r == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(r.routes))
	out := make([]string, 0, len(r.routes))

	for _, cr := range r.routes {
		if _, dup := seen[cr.route.BackendID]; dup {
			continue
		}
		seen[cr.route.BackendID] = struct{}{}
		out = append(out, cr.route.BackendID)
	}

	sort.Strings(out)
	return out
}

// ValidateBackends checks that every backend a route names actually exists.
//
// Without this the gateway starts cleanly with a route pointing at a backend
// that was never configured, and the mismatch only surfaces when a real
// request hits that route -- as a 502 for the caller and a page for whoever is
// on call. A typo in routes.yaml or a missing entry in GATEWAY_BACKENDS_JSON
// should fail the deploy instead.
func (r *Registry) ValidateBackends(configured map[string]struct{}) error {
	var missing []string

	for _, id := range r.BackendIDs() {
		if _, ok := configured[id]; !ok {
			missing = append(missing, id)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	available := make([]string, 0, len(configured))
	for id := range configured {
		available = append(available, id)
	}
	sort.Strings(available)

	return fmt.Errorf(
		"routes reference backends that are not configured: %s (configured: %s)",
		strings.Join(missing, ", "), strings.Join(available, ", "))
}
