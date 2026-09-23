package keys_test

import (
	"testing"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

func TestProofRoundTrip(t *testing.T) {
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	now := time.Now().UTC()
	proof, err := keys.SignProof(kp.PrivateKey, "tenant-a", "agent-a", kp.KeyID, now)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	if err := keys.VerifyProof(kp.PublicKey, "tenant-a", "agent-a", kp.KeyID, proof, now, now); err != nil {
		t.Fatalf("verify proof: %v", err)
	}
}

// TestProofRequiresTheMatchingPrivateKey is the property that makes
// registration meaningful: you cannot register a key you do not hold.
func TestProofRequiresTheMatchingPrivateKey(t *testing.T) {
	victim, _ := keys.Generate()
	attacker, _ := keys.Generate()

	now := time.Now().UTC()

	// The attacker signs with their own key but submits the victim's key id.
	proof, err := keys.SignProof(attacker.PrivateKey, "tenant-a", "agent-a", victim.KeyID, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := keys.VerifyProof(victim.PublicKey, "tenant-a", "agent-a", victim.KeyID, proof, now, now); err == nil {
		t.Fatal("a proof signed by a different key was accepted")
	}
}

// TestProofIsBoundToItsFields: a proof for one tenant/agent/key must not be
// reusable for another.
func TestProofIsBoundToItsFields(t *testing.T) {
	kp, _ := keys.Generate()
	now := time.Now().UTC()

	proof, err := keys.SignProof(kp.PrivateKey, "tenant-a", "agent-a", kp.KeyID, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	cases := map[string][3]string{
		"different tenant": {"tenant-b", "agent-a", kp.KeyID},
		"different agent":  {"tenant-a", "agent-b", kp.KeyID},
	}

	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if err := keys.VerifyProof(kp.PublicKey, f[0], f[1], f[2], proof, now, now); err == nil {
				t.Error("a proof was accepted for fields it was not signed over")
			}
		})
	}
}

func TestStaleProofRejected(t *testing.T) {
	kp, _ := keys.Generate()
	issued := time.Now().UTC().Add(-keys.ProofMaxAge - time.Minute)

	proof, err := keys.SignProof(kp.PrivateKey, "t", "a", kp.KeyID, issued)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := keys.VerifyProof(kp.PublicKey, "t", "a", kp.KeyID, proof,
		issued, time.Now().UTC()); err == nil {
		t.Fatal("a stale proof was accepted")
	}
}

// TestFieldInjectionViaIdentifier covers why the proof input is
// length-prefixed: a crafted identifier must not be able to shift field
// boundaries so that one proof reads as a proof for different fields.
func TestFieldInjectionViaIdentifier(t *testing.T) {
	a := keys.ProofInput("tenant", "agent:extra", "kid", time.Unix(0, 0))
	b := keys.ProofInput("tenant", "agent", "extra:kid", time.Unix(0, 0))

	if string(a) == string(b) {
		t.Error("two different field sets produced identical proof input")
	}
}
