package signer_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/signer"
)

// principalContext builds a message in the principal-context canonical form:
// the prefix, then each field as length-prefixed lowercase name and value,
// sorted by name. It is the form a gateway signs through the daemon.
func principalContext(fields map[string]string) []byte {
	lower := make(map[string]string, len(fields))
	names := make([]string, 0, len(fields))
	for k, v := range fields {
		k = strings.ToLower(k)
		lower[k] = v
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("agw-principal-context-v1\n")
	for _, k := range names {
		fmt.Fprintf(&b, "%d:%s%d:%s", len(k), k, len(lower[k]), lower[k])
	}
	return []byte(b.String())
}

// realAssertion is a complete principal context, with every field a gateway
// asserts.
func realAssertion() []byte {
	return principalContext(map[string]string{
		"X-AGW-Verified-Tenant-Id": "tenant-alpha",
		"X-AGW-Verified-Agent-Id":  "agent-support-01",
		"X-AGW-Verified-Key-Id":    "k1",
		"X-AGW-Verified-Action":    "github.issue.create",
		"X-AGW-Verified-Resource":  "acme/app",
		"X-AGW-Decision-Id":        "dec_abc123",
		"X-AGW-Auth-Time":          "2026-09-19T10:00:00Z",
		"X-AGW-Expires-At":         "2026-09-19T10:01:00Z",
	})
}

// realCheckpoint mirrors audit.canonicalCheckpointInput.
func realCheckpoint() []byte {
	var b strings.Builder
	b.WriteString("agw-evidence-v1/checkpoint\n")
	write := func(s string) { fmt.Fprintf(&b, "%d:%s", len(s), s) }
	write("1043")
	write("7be2a91f")
	write("1043")
	write("2026-09-19T10:00:00Z")
	write("checkpoint-key-1")
	return []byte(b.String())
}

// TestDaemonRefusesArbitraryBytes is the whole point of this change.
//
// Before it, socket access to the daemon was an unlimited signing oracle: any
// byte string handed in came back signed with the gateway's key. That is the
// primitive the July 2026 Hugging Face intruder used once it had a signing
// key -- mint whatever you like, correctly signed.
func TestDaemonRefusesArbitraryBytes(t *testing.T) {
	hostile := map[string][]byte{
		"plain text":              []byte("hello"),
		"a JWT header":            []byte(`{"alg":"EdDSA","typ":"JWT"}`),
		"someone else's proto":    []byte("ssh-userauth\x00\x00\x00\x20"),
		"empty-ish":               []byte(" "),
		"a near-miss prefix":      []byte("agw-principal-context-v2\n8:tenantid"),
		"prefix with no body":     []byte("agw-principal-context-v1\n"),
		"checkpoint near-miss":    []byte("agw-evidence-v1/checkpoints\n4:1043"),
		"raw AGS1 signature base": []byte("\"@method\": POST\n\"@authority\": gw.example.com"),
	}

	for name, msg := range hostile {
		t.Run(name, func(t *testing.T) {
			p, err := signer.ClassifyPurpose(msg)
			if err != nil {
				return // refused at classification, which is correct
			}
			// It matched a prefix, so the structural check must refuse it.
			if err := signer.ValidateForPurpose(p, msg); err == nil {
				t.Errorf("%q was accepted as purpose %q", msg, p)
			}
		})
	}
}

// TestAppendedBytesAreRefused covers the obvious bypass: take a valid
// message and staple a payload to the end of it.
func TestAppendedBytesAreRefused(t *testing.T) {
	cases := map[string][]byte{
		"assertion":  realAssertion(),
		"checkpoint": realCheckpoint(),
		"probe":      signer.ReadinessProbeMessage,
	}

	for name, valid := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := signer.ClassifyPurpose(valid)
			if err != nil {
				t.Fatalf("a valid %s did not classify: %v", name, err)
			}
			if err := signer.ValidateForPurpose(p, valid); err != nil {
				t.Fatalf("a valid %s did not validate: %v", name, err)
			}

			tampered := append(append([]byte{}, valid...), []byte("payload-the-attacker-wants-signed")...)
			if err := signer.ValidateForPurpose(p, tampered); err == nil {
				t.Errorf("%s with appended bytes was accepted", name)
			}
		})
	}
}

// TestRealCanonicalFormsAreAccepted is the regression guard in the other
// direction: if the daemon's view of a canonical form changes, this fails
// rather than a producer silently losing the ability to sign.
func TestRealCanonicalFormsAreAccepted(t *testing.T) {
	cases := map[string]struct {
		msg  []byte
		want string
	}{
		"assertion":  {realAssertion(), signer.PurposePrincipalContext},
		"checkpoint": {realCheckpoint(), signer.PurposeEvidenceCheckpoint},
		"probe":      {signer.ReadinessProbeMessage, signer.PurposeReadinessProbe},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := signer.ClassifyPurpose(tc.msg)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if got != tc.want {
				t.Errorf("purpose = %q, want %q", got, tc.want)
			}
			if err := signer.ValidateForPurpose(got, tc.msg); err != nil {
				t.Errorf("validate: %v", err)
			}
		})
	}
}

// TestAssertionWithoutIdentityIsRefused: an assertion the daemon signs must
// actually assert an identity, or it is not doing the job it exists for.
func TestAssertionWithoutIdentityIsRefused(t *testing.T) {
	msg := principalContext(map[string]string{
		"X-AGW-Verified-Action": "github.repo.delete",
	})
	if err := signer.ValidateForPurpose(signer.PurposePrincipalContext, msg); err == nil {
		t.Error("an assertion with no tenant, agent or decision id was accepted")
	}
}

func TestReadinessProbeMustBeExact(t *testing.T) {
	near := []byte("agw-readiness-probe-v1\nreadinesss")
	if err := signer.ValidateForPurpose(signer.PurposeReadinessProbe, near); err == nil {
		t.Error("a near-miss readiness probe was accepted")
	}
	if err := signer.ValidateForPurpose(signer.PurposeReadinessProbe, signer.ReadinessProbeMessage); err != nil {
		t.Errorf("the canonical readiness probe was refused: %v", err)
	}
}

// --- daemon-level enforcement -------------------------------------------

// startConfiguredDaemon starts a daemon with a specific purpose/rate config.
// signer_test.go has its own startDaemon for the default case; this one exists
// because these tests need to vary DaemonConfig.
func startConfiguredDaemon(t *testing.T, cfg signer.DaemonConfig) (*signer.Daemon, *signer.SeparatedSigner) {
	t.Helper()

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	held, err := signer.FromKey(kp.PrivateKey, kp.KeyID)
	if err != nil {
		t.Fatalf("file signer: %v", err)
	}

	cfg.Signer = held
	cfg.SocketPath = shortSocketPath(t)

	d, err := signer.NewDaemon(cfg)
	if err != nil {
		t.Fatalf("daemon: %v", err)
	}
	go func() { _ = d.Serve() }()
	t.Cleanup(func() { _ = d.Close() })

	client, err := signer.Connect(signer.SeparatedConfig{SocketPath: cfg.SocketPath})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return d, client
}

// TestDaemonRefusesOverTheSocket proves the control is enforced where it
// matters, not merely available as a function someone could forget to call.
func TestDaemonRefusesOverTheSocket(t *testing.T) {
	d, client := startConfiguredDaemon(t, signer.DaemonConfig{})

	if _, err := client.Sign([]byte("arbitrary bytes an attacker wants signed")); err == nil {
		t.Fatal("the daemon signed arbitrary bytes over the socket")
	}

	// A legitimate message still works, so the refusal is the purpose check
	// rather than a broken daemon.
	if _, err := client.Sign(realAssertion()); err != nil {
		t.Fatalf("a valid assertion was refused: %v", err)
	}

	signed, refused := d.PurposeStats()
	if signed[signer.PurposePrincipalContext] != 1 {
		t.Errorf("signed[principal-context] = %d, want 1", signed[signer.PurposePrincipalContext])
	}
	if refused["unknown"] != 1 {
		t.Errorf("refused[unknown] = %d, want 1", refused["unknown"])
	}
}

// TestDaemonServingOnePurposeRefusesTheOther is the split-custody property:
// a daemon holding the checkpoint key must not be usable to mint assertions.
func TestDaemonServingOnePurposeRefusesTheOther(t *testing.T) {
	_, client := startConfiguredDaemon(t, signer.DaemonConfig{
		Purposes: []string{signer.PurposeEvidenceCheckpoint},
	})

	if _, err := client.Sign(realCheckpoint()); err != nil {
		t.Fatalf("checkpoint refused by a checkpoint daemon: %v", err)
	}
	if _, err := client.Sign(realAssertion()); err == nil {
		t.Error("a checkpoint-only daemon minted a principal assertion")
	}
}

// TestSigningIsRateLimited turns a silent harvest into a visible failure.
func TestSigningIsRateLimited(t *testing.T) {
	d, client := startConfiguredDaemon(t, signer.DaemonConfig{
		SignsPerSecond: 1,
		Burst:          5,
	})

	var ok, denied int
	for i := 0; i < 40; i++ {
		if _, err := client.Sign(realAssertion()); err != nil {
			denied++
		} else {
			ok++
		}
	}

	if denied == 0 {
		t.Fatalf("no request was rate limited after 40 signatures (ok=%d)", ok)
	}
	if ok == 0 {
		t.Fatal("every request was refused; the limiter is not letting legitimate traffic through")
	}
	t.Logf("signed %d, rate limited %d", ok, denied)

	if _, refused := d.PurposeStats(); refused[signer.PurposePrincipalContext] == 0 {
		t.Error("rate-limited requests were not counted against their purpose")
	}
}

// TestReadinessProbeWorksThroughADaemon covers the exact path a producer
// uses to decide the daemon is ready to serve.
//
// Purpose enforcement very nearly broke this: the readiness check signed the
// literal "agw-readiness-probe", which the daemon would have refused, and the
// gateway would never have become ready. A unit test of the validators alone
// would not have caught it.
func TestReadinessProbeWorksThroughADaemon(t *testing.T) {
	_, client := startConfiguredDaemon(t, signer.DaemonConfig{})

	if _, err := client.Sign(signer.ReadinessProbeMessage); err != nil {
		t.Fatalf("the gateway readiness probe was refused: %v", err)
	}
}

// TestCheckpointOnlyDaemonStillAnswersReadiness: a split-custody deployment
// must still be able to tell whether its checkpoint daemon is alive.
func TestCheckpointOnlyDaemonStillAnswersReadiness(t *testing.T) {
	_, client := startConfiguredDaemon(t, signer.DaemonConfig{
		Purposes: []string{signer.PurposeEvidenceCheckpoint, signer.PurposeReadinessProbe},
	})

	if _, err := client.Sign(signer.ReadinessProbeMessage); err != nil {
		t.Fatalf("readiness refused: %v", err)
	}
	if _, err := client.Sign(realAssertion()); err == nil {
		t.Error("a checkpoint daemon minted a principal assertion")
	}
}
