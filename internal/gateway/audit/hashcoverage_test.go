package audit

import (
	"reflect"
	"testing"
	"time"
)

// TestHashCoversEveryEventField is the guard on a whole class of bug, not on
// one instance of it.
//
// canonicalRecordInput hands the hasher an explicit list of fields. That list
// is maintained by hand, and it drifted: SourceTenant, Federated, TrustGrant
// and Risk were added to GatewayEvent during the federation and hardening
// work and never added to the hash. For as long as that held, an attacker
// with write access to an evidence log could reassign a partner's actions to
// another organization, make a federated call look local, or lower a
// destructive action's recorded risk to read -- and verification still
// passed.
//
// Rather than re-checking those four, this walks GatewayEvent by reflection,
// changes each field in turn, and requires the hash to move. A field added to
// the struct and forgotten here fails the build instead of quietly leaving a
// hole in the one property the product is sold on.
func TestHashCoversEveryEventField(t *testing.T) {
	base := Record{
		Version:   ChainVersion,
		Seq:       42,
		EventName: "gateway.request.allowed",
		Timestamp: time.Unix(1789000000, 0).UTC(),
		PrevHash:  "abc123",
		Event: GatewayEvent{
			EventID: "ev", TenantID: "acme", AgentID: "agent-1", KeyID: "k",
			DecisionID: "dec", RequestID: "req", TraceID: "tr",
			SourceTenant: "partner-b", Federated: true, TrustGrant: "grant-1",
			RouteID: "r", Action: "github.issue.create", ResourceType: "repo",
			ResourceID: "acme/app", BackendID: "gh", Risk: "destructive",
			Decision: "allow", ReasonCode: "allowed", HTTPStatus: 200,
			SourceIP: "10.0.0.1", UserAgent: "ua",
			StartedAt:  time.Unix(1789000000, 0).UTC(),
			FinishedAt: time.Unix(1789000001, 0).UTC(),
			LatencyMS:  1000,
		},
	}
	original := ComputeHash(base)

	rt := reflect.TypeOf(base.Event)
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}

		t.Run(field.Name, func(t *testing.T) {
			mutated := base
			fv := reflect.ValueOf(&mutated.Event).Elem().Field(i)

			if !mutateField(fv) {
				t.Skipf("no mutation strategy for %s (%s); add one rather than "+
					"leaving the field unchecked", field.Name, field.Type)
			}

			if ComputeHash(mutated) == original {
				t.Errorf("changing %s does not change the record hash, so it can be "+
					"edited in an evidence log without breaking verification. "+
					"Add it to canonicalRecordInput.", field.Name)
			}
		})
	}
}

// mutateField changes a value in a type-appropriate way. Returns false when
// the type is not handled, so an unhandled type is reported rather than
// silently passing.
func mutateField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "-changed")
		return true
	case reflect.Bool:
		v.SetBool(!v.Bool())
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Type() == reflect.TypeOf(time.Duration(0)) {
			v.SetInt(v.Int() + int64(time.Second))
			return true
		}
		v.SetInt(v.Int() + 1)
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
		return true
	case reflect.Struct:
		if t, ok := v.Interface().(time.Time); ok {
			v.Set(reflect.ValueOf(t.Add(time.Hour)))
			return true
		}
		return false
	default:
		return false
	}
}

// TestV1RecordsStillVerifyUnderV1Rules: a log written by the superseded
// format must not start failing because the format moved on. It is the
// verifier's job to say what v1 cannot protect, not to call it corrupt.
func TestV1RecordsStillVerifyUnderV1Rules(t *testing.T) {
	r := Record{
		Version:   ChainVersionV1,
		Seq:       1,
		EventName: "x",
		Timestamp: time.Unix(1789000000, 0).UTC(),
		PrevHash:  GenesisHash,
		Event:     GatewayEvent{TenantID: "acme", Decision: "allow"},
	}
	r.Hash = ComputeHash(r)

	if ComputeHash(r) != r.Hash {
		t.Fatal("a v1 record does not reproduce its own hash")
	}

	// And the v2 fields are, correctly, still unprotected in v1 -- which is
	// exactly what the verifier reports rather than hides.
	mutated := r
	mutated.Event.SourceTenant = "someone-else"
	if ComputeHash(mutated) != r.Hash {
		t.Error("v1 hashing changed; a v1 log written earlier would now fail to verify")
	}
}
