package routing

type RiskClass string

const (
	RiskRead        RiskClass = "read"
	RiskWrite       RiskClass = "write"
	RiskPrivileged  RiskClass = "privileged"
	RiskDestructive RiskClass = "destructive"
)

type Route struct {
	ID                 string            `yaml:"id"`
	Method             string            `yaml:"method"`
	PathPattern        string            `yaml:"path_pattern"`
	Action             string            `yaml:"action"`
	ResourceType       string            `yaml:"resource_type"`
	ResourceIDTemplate string            `yaml:"resource_id_template"`
	BackendID          string            `yaml:"backend_id"`
	RiskClass          RiskClass         `yaml:"risk_class"`
	Headers            map[string]string `yaml:"headers,omitempty"`
}

type MatchResult struct {
	Route        Route
	PathVars     map[string]string
	Action       string
	ResourceType string
	ResourceID   string
	BackendID    string
}
