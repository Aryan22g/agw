package protocol_test

import (
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// TestReplayTTLOutlastsAcceptanceWindow pins the invariant that a nonce
// reservation cannot lapse while the request it protects is still acceptable.
//
// These two values were equal in the original profile (360s each), leaving a
// zero-margin race in which a captured request could be replayed just as its
// reservation expired. Asserting it here means a future tuning change to
// either constant cannot silently reopen that window.
func TestReplayTTLOutlastsAcceptanceWindow(t *testing.T) {
	if protocol.AcceptanceWindowSeconds != protocol.MaxRequestAgeSeconds+protocol.MaxClockSkewSeconds {
		t.Fatalf("AcceptanceWindowSeconds (%d) does not equal age + skew (%d + %d)",
			protocol.AcceptanceWindowSeconds,
			protocol.MaxRequestAgeSeconds, protocol.MaxClockSkewSeconds)
	}

	if protocol.ReplayTTLSeconds <= protocol.AcceptanceWindowSeconds {
		t.Fatalf("ReplayTTLSeconds (%d) must exceed the acceptance window (%d); "+
			"a nonce that expires while its request is still valid is replayable",
			protocol.ReplayTTLSeconds, protocol.AcceptanceWindowSeconds)
	}

	// Require real headroom, not a one-second technicality: clocks drift
	// between nodes and key expiry is not instantaneous.
	if margin := protocol.ReplayTTLSeconds - protocol.AcceptanceWindowSeconds; margin < 120 {
		t.Errorf("replay TTL margin is only %ds; want at least 120s of headroom", margin)
	}
}
