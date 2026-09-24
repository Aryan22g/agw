package routing

import (
	"fmt"
	"regexp"
	"strings"
)

var pathVarNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type compiledRoute struct {
	route Route
	re    *regexp.Regexp
	vars  []string
}

func compilePathPattern(pattern string) (*regexp.Regexp, []string, error) {
	if pattern == "" {
		return nil, nil, fmt.Errorf("%w: empty path pattern", ErrInvalidPathPattern)
	}
	if pattern[0] != '/' {
		return nil, nil, fmt.Errorf("%w: must start with /: %q", ErrInvalidPathPattern, pattern)
	}

	parts := strings.Split(pattern, "/")
	var (
		builder strings.Builder
		vars    []string
	)

	builder.WriteString("^")

	for i, part := range parts {
		if i == 0 {
			continue
		}

		builder.WriteString("/")

		if part == "" {
			continue
		}

		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.TrimSpace(part[1 : len(part)-1])
			if !pathVarNameRE.MatchString(name) {
				return nil, nil, fmt.Errorf("%w: invalid variable name %q", ErrInvalidPathPattern, name)
			}
			vars = append(vars, name)
			builder.WriteString("(?P<")
			builder.WriteString(name)
			builder.WriteString(`>[^/]+)`)
			continue
		}

		builder.WriteString(regexp.QuoteMeta(part))
	}

	builder.WriteString("$")

	re, err := regexp.Compile(builder.String())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPathPattern, err)
	}

	return re, vars, nil
}

func extractVars(re *regexp.Regexp, vars []string, path string) (map[string]string, bool) {
	matches := re.FindStringSubmatch(path)
	if matches == nil {
		return nil, false
	}

	out := make(map[string]string, len(vars))
	for i, name := range vars {
		if i+1 >= len(matches) {
			return nil, false
		}
		out[name] = matches[i+1]
	}
	return out, true
}

func renderTemplate(template string, vars map[string]string) (string, error) {
	if template == "" {
		return "", fmt.Errorf("%w: empty resource_id_template", ErrInvalidTemplate)
	}

	re := regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	missing := false

	out := re.ReplaceAllStringFunc(template, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if len(sub) != 2 {
			missing = true
			return m
		}
		name := sub[1]
		val, ok := vars[name]
		if !ok {
			missing = true
			return m
		}
		return val
	})

	if missing || strings.Contains(out, "{") || strings.Contains(out, "}") {
		return "", fmt.Errorf("%w: missing variables for template %q", ErrInvalidTemplate, template)
	}

	return out, nil
}

func validateRoute(r Route) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidRoute)
	}
	if strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("%w: missing method", ErrInvalidRoute)
	}
	if strings.TrimSpace(r.PathPattern) == "" {
		return fmt.Errorf("%w: missing path_pattern", ErrInvalidRoute)
	}
	if strings.TrimSpace(r.Action) == "" {
		return fmt.Errorf("%w: missing action", ErrInvalidRoute)
	}
	if strings.TrimSpace(r.ResourceType) == "" {
		return fmt.Errorf("%w: missing resource_type", ErrInvalidRoute)
	}
	if strings.TrimSpace(r.ResourceIDTemplate) == "" {
		return fmt.Errorf("%w: missing resource_id_template", ErrInvalidRoute)
	}
	if strings.TrimSpace(r.BackendID) == "" {
		return fmt.Errorf("%w: missing backend_id", ErrInvalidRoute)
	}
	switch r.RiskClass {
	case RiskRead, RiskWrite, RiskPrivileged, RiskDestructive:
	default:
		return fmt.Errorf("%w: invalid risk_class %q", ErrInvalidRoute, r.RiskClass)
	}
	return nil
}
