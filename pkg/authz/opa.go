package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Aryan22g/agw/pkg/decision"
)

// OPAConfig configures the optional Open Policy Agent backend.
type OPAConfig struct {
	// QueryURL is a full OPA data API URL, e.g.
	// http://localhost:8181/v1/data/ags1/authz/allow
	QueryURL string

	BearerToken string
	Timeout     time.Duration
}

// OPAEngine evaluates authorization against an external OPA deployment.
//
// This is an opt-in alternative to NativeEngine for teams that already run
// Rego. It is not the default: it puts a network call on the request path,
// and because the gateway fails closed, an OPA outage becomes a traffic
// outage. Teams choosing it are choosing that trade knowingly.
type OPAEngine struct {
	client *http.Client
	cfg    OPAConfig
}

// NewOPAEngine builds an OPA-backed engine.
func NewOPAEngine(cfg OPAConfig) (*OPAEngine, error) {
	if cfg.QueryURL == "" {
		return nil, fmt.Errorf("opa: query url is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	return &OPAEngine{
		client: &http.Client{Timeout: cfg.Timeout},
		cfg:    cfg,
	}, nil
}

type opaRequest struct {
	Input opaInput `json:"input"`
}

type opaInput struct {
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	RiskClass string `json:"risk_class"`
	Timestamp string `json:"timestamp"`
}

type opaResponse struct {
	// Result is a pointer so that "key absent" and "explicit false" are
	// distinguishable. An absent result means the Rego rule did not
	// produce a decision, which must not be read as allow.
	Result *bool `json:"result"`
}

// Authorize queries OPA and maps the response onto a gateway decision.
func (e *OPAEngine) Authorize(ctx context.Context, req Request) decision.Decision {
	payload := opaRequest{Input: opaInput{
		TenantID:  req.TenantID,
		AgentID:   req.AgentID,
		Action:    req.Action,
		Resource:  req.Resource,
		RiskClass: string(req.RiskClass),
		Timestamp: req.Now.UTC().Format(time.RFC3339),
	}}

	body, err := json.Marshal(payload)
	if err != nil {
		return decision.Fail(decision.ReasonInternalError, err, "marshal opa input")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.QueryURL, bytes.NewReader(body))
	if err != nil {
		return decision.Fail(decision.ReasonInternalError, err, "build opa request")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.cfg.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.cfg.BearerToken)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return decision.Fail(decision.ReasonDependencyUnavailable, err, "opa unreachable")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return decision.Fail(decision.ReasonDependencyUnavailable, nil,
			fmt.Sprintf("opa returned %d: %s", resp.StatusCode, snippet))
	}

	var out opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return decision.Fail(decision.ReasonDependencyUnavailable, err, "opa response is not valid json")
	}

	// A missing result is a policy that did not decide. Treated as an
	// infrastructure failure rather than a denial so it pages someone,
	// instead of quietly looking like an agent misbehaving.
	if out.Result == nil {
		return decision.Fail(decision.ReasonDependencyUnavailable, nil,
			"opa returned no decision; check the query path")
	}

	if !*out.Result {
		return decision.Deny(decision.ReasonPolicyDenied, nil,
			fmt.Sprintf("opa denied %s on %s for agent %s", req.Action, req.Resource, req.AgentID))
	}

	return decision.Allow()
}
