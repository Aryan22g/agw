package gym

import (
	"io"
	"log/slog"
	"testing"
)

// newTestHarness builds a gym in a temp directory and tears it down after.
func newTestHarness(t *testing.T, seed uint64) *Harness {
	t.Helper()
	h, err := NewHarness(HarnessConfig{
		Seed: seed,
		Dir:  t.TempDir(),
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("build harness: %v", err)
	}
	t.Cleanup(h.Close)
	return h
}

// TestGymRunsCleanOnAFixedSeed is the regression the gym exists to provide: a
// full adversarial run against the real enforcement code, scored against the
// world's own receipt log rather than the product's account of itself.
//
// It is a single seed so the test stays fast. The sweep over many seeds is a
// separate command, because that is a minutes-long job and belongs in CI
// rather than in `go test`.
func TestGymRunsCleanOnAFixedSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("the gym stands up a world and a proxy; not a short test")
	}

	h := newTestHarness(t, 20260920)
	results, err := Run(h, BuildEpisodes(h))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	h.Close()

	score, err := Grade(h, results, 20260920)
	if err != nil {
		t.Fatalf("grade: %v", err)
	}

	for _, r := range score.Results {
		if !r.Passed {
			t.Errorf("%s (%s): %s -- %s", r.ID, r.Family, r.Outcome, r.Detail)
		}
	}

	// The oracle. Everything else in this file reads what the product said
	// about itself; this is the world saying what it received.
	if n := len(score.UnrecordedEgress); n > 0 {
		t.Errorf("%d requests reached a service with no evidence record", n)
		for i, hit := range score.UnrecordedEgress {
			if i == 5 {
				break
			}
			t.Logf("  unrecorded: %s %s:%d%s", hit.Method, hit.Host, hit.Port, hit.Path)
		}
	}

	// A run that blocked everything would pass every containment check and
	// mean nothing, so the benign traffic has to have got through.
	if score.BenignAttempted == 0 {
		t.Fatal("no benign episodes ran: containment cannot be interpreted without them")
	}
	if score.FalsePositives > 0 {
		t.Errorf("%d/%d legitimate requests were refused",
			score.FalsePositives, score.BenignAttempted)
	}

	if score.WorldRequests == 0 {
		t.Fatal("the world served no requests: the gym did not actually exercise anything")
	}
}

// TestEveryTamperIsDetected checks the claim the evidence chain is sold on,
// against a chain produced by real traffic rather than a synthetic fixture.
func TestEveryTamperIsDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real chain with real traffic in it")
	}

	h := newTestHarness(t, 7)
	results, err := Run(h, BuildEpisodes(h))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	h.Close()

	score, err := Grade(h, results, 7)
	if err != nil {
		t.Fatalf("grade: %v", err)
	}

	for _, tamper := range score.Tampers {
		if !tamper.Detected {
			t.Errorf("%s was not detected: %s", tamper.Kind, tamper.Detail)
			continue
		}
		// Truncation at a checkpoint boundary is detectable only with state
		// kept outside the file. That is a property of the format, not a
		// defect, so it is asserted rather than flagged -- if it ever starts
		// being caught by the file alone, that is worth knowing too.
		if tamper.Kind == TamperTruncateAfterCheckpoint && tamper.ByChain {
			t.Logf("%s is now caught by the file alone; the anchor may no longer be required",
				tamper.Kind)
		}
		if !tamper.ByChain && !tamper.ByAnchor {
			t.Errorf("%s is marked detected but by neither route", tamper.Kind)
		}
	}
}

// TestWorldIsReproducibleFromItsSeed pins the property contained mode depends
// on: two processes that never speak to each other derive the same topology,
// including the canary tokens, from the seed alone.
func TestWorldIsReproducibleFromItsSeed(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	a, policyA, err := NewGenerator(99).DescribeOnly("w", discard)
	if err != nil {
		t.Fatal(err)
	}
	b, policyB, err := NewGenerator(99).DescribeOnly("w", discard)
	if err != nil {
		t.Fatal(err)
	}

	if len(a.Services) != len(b.Services) {
		t.Fatalf("service count differs: %d vs %d", len(a.Services), len(b.Services))
	}
	for i := range a.Services {
		x, y := a.Services[i], b.Services[i]
		if x.Hostname != y.Hostname || x.Port != y.Port || x.InPolicy != y.InPolicy {
			t.Errorf("service %d differs: %+v vs %+v", i, x, y)
		}
	}

	// The canaries matter most. When they were minted from crypto/rand, the
	// agent container exfiltrated secrets the world container had never
	// issued, and every escape went unnoticed.
	if len(a.Canaries) == 0 {
		t.Fatal("no canaries were planted")
	}
	for token, origin := range a.Canaries {
		if b.Canaries[token] != origin {
			t.Errorf("canary %s is missing or differently attributed in the second world", token)
		}
	}

	if len(policyA.Workloads) != len(policyB.Workloads) {
		t.Errorf("policies differ in shape: %d vs %d workloads",
			len(policyA.Workloads), len(policyB.Workloads))
	}
}

// TestSkippedEpisodesAreNotCountedAsPasses guards a way the report could
// quietly become dishonest: a mode that cannot run a control should show a
// gap, not a full bar.
func TestSkippedEpisodesAreNotCountedAsPasses(t *testing.T) {
	h := newTestHarness(t, 3)

	// Take away every in-process capability, as contained mode does.
	h.Caps = map[Capability]bool{}

	results, err := Run(h, BuildEpisodes(h))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	h.Close()

	score, err := Grade(h, results, 3)
	if err != nil {
		t.Fatalf("grade: %v", err)
	}

	if score.Skipped == 0 {
		t.Fatal("no episodes were skipped although every capability was withdrawn")
	}
	for _, r := range score.Results {
		if r.Outcome != "skipped" {
			continue
		}
		if fs := score.ByFamily[r.Family]; fs != nil && fs.Total > 0 {
			// A family may still have runnable episodes; what must not happen
			// is a skipped one being counted among them.
			for _, other := range score.Results {
				if other.ID == r.ID && other.Outcome == "skipped" && other.Family == r.Family {
					break
				}
			}
		}
	}
	if score.Passed+score.Failed+score.Skipped != score.Episodes {
		t.Errorf("episode accounting does not add up: %d passed + %d failed + %d skipped != %d",
			score.Passed, score.Failed, score.Skipped, score.Episodes)
	}
}
