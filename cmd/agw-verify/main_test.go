package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const corpusPath = "../../conformance/evidence/agw-evidence-v2.json"

type corpusFile struct {
	PublicKey   string `json:"public_key"`
	HashVectors []struct {
		Name           string `json:"name"`
		Record         string `json:"record"`
		CanonicalInput string `json:"canonical_input"`
		Hash           string `json:"hash"`
	} `json:"hash_vectors"`
	VerifyVectors []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Log         string          `json:"log"`
		Key         string          `json:"key"`
		Anchor      json.RawMessage `json:"anchor"`
		Expect      struct {
			Intact            bool   `json:"intact"`
			Records           uint64 `json:"records"`
			Checkpoints       uint64 `json:"checkpoints"`
			HeadSeq           uint64 `json:"head_seq"`
			SignedThrough     uint64 `json:"signed_through"`
			UnanchoredRecords uint64 `json:"unanchored_records"`
			Problems          []struct {
				Kind string `json:"kind"`
				Seq  uint64 `json:"seq"`
			} `json:"problems"`
		} `json:"expect"`
	} `json:"verify_vectors"`
}

func loadCorpus(t *testing.T) corpusFile {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var c corpusFile
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestConformsToCorpus: this verifier, written from RFC-0009, reproduces
// every expected result in the corpus.
func TestConformsToCorpus(t *testing.T) {
	c := loadCorpus(t)
	pubRaw, _ := base64.StdEncoding.DecodeString(c.PublicKey)

	for _, hv := range c.HashVectors {
		_, r, _, err := classify([]byte(hv.Record))
		if err != nil {
			t.Fatalf("hash vector %q: %v", hv.Name, err)
		}
		in, err := hashInput(r)
		if err != nil {
			t.Fatal(err)
		}
		if in != hv.CanonicalInput {
			t.Errorf("hash vector %q:\n got %q\nwant %q", hv.Name, in, hv.CanonicalInput)
		}
		if sha256hex(in) != hv.Hash {
			t.Errorf("hash vector %q: hash mismatch", hv.Name)
		}
	}

	for _, v := range c.VerifyVectors {
		t.Run(v.Name, func(t *testing.T) {
			var pub ed25519.PublicKey
			if v.Key == "test" {
				pub = pubRaw
			}
			var anchor *checkpoint
			if len(v.Anchor) > 0 {
				_, _, cp, err := classify(v.Anchor)
				if err != nil {
					t.Fatal(err)
				}
				anchor = &cp
			}
			res, err := Verify(strings.NewReader(v.Log), pub, anchor)
			if err != nil {
				t.Fatal(err)
			}
			type kp struct {
				Kind string
				Seq  uint64
			}
			var got, want []kp
			for _, p := range res.Problems {
				got = append(got, kp{p.Kind, p.Seq})
			}
			for _, p := range v.Expect.Problems {
				want = append(want, kp{p.Kind, p.Seq})
			}
			e := v.Expect
			if res.Intact != e.Intact || res.Records != e.Records || res.Checkpoints != e.Checkpoints ||
				res.HeadSeq != e.HeadSeq || res.SignedThrough != e.SignedThrough ||
				res.UnanchoredRecords != e.UnanchoredRecords || !reflect.DeepEqual(got, want) {
				t.Errorf("%s\n got  intact=%v records=%d cps=%d head=%d signed=%d unanchored=%d %v\n want %+v",
					v.Description, res.Intact, res.Records, res.Checkpoints, res.HeadSeq,
					res.SignedThrough, res.UnanchoredRecords, got, e)
			}
		})
	}
}

// TestImportsOnlyTheStandardLibrary is what makes this an independent
// implementation rather than a wrapper: if it ever imports the reference
// code, agreement between the two proves nothing.
func TestImportsOnlyTheStandardLibrary(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, line := range strings.Fields(string(out)) {
		if line != "github.com/Aryan22g/agw/cmd/agw-verify" {
			t.Errorf("agw-verify depends on non-standard package %s", line)
		}
	}
}

func TestExitStatus(t *testing.T) {
	c := loadCorpus(t)
	dir := t.TempDir()
	keyFile := dir + "/k.pub"
	_ = os.WriteFile(keyFile, []byte(c.PublicKey+"\n"), 0o644)

	cases := map[string]int{"intact_fully_anchored": 0, "content_edited": 2}
	for _, v := range c.VerifyVectors {
		want, ok := cases[v.Name]
		if !ok {
			continue
		}
		path := dir + "/" + v.Name + ".jsonl"
		_ = os.WriteFile(path, []byte(v.Log), 0o644)
		var out, errb bytes.Buffer
		if got := run([]string{path, "--key", keyFile}, &out, &errb); got != want {
			t.Errorf("%s: exit %d, want %d\n%s%s", v.Name, got, want, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	if got := run([]string{dir + "/missing.jsonl"}, &out, &errb); got != 1 {
		t.Errorf("missing file: exit %d, want 1", got)
	}
}

// mutate applies one random, plausible edit to a log. Some produce valid
// logs, most do not; the test does not care which, only that both
// implementations agree.
func mutate(r *rand.Rand, log string) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	i := r.IntN(len(lines))
	switch r.IntN(10) {
	case 0: // delete a line
		lines = append(lines[:i], lines[i+1:]...)
	case 1: // duplicate a line
		lines = append(lines[:i+1], lines[i:]...)
	case 2: // swap two lines
		j := r.IntN(len(lines))
		lines[i], lines[j] = lines[j], lines[i]
	case 3: // flip one character
		if len(lines[i]) > 0 {
			b := []byte(lines[i])
			k := r.IntN(len(b))
			b[k] ^= byte(1 + r.IntN(0x3f))
			lines[i] = string(b)
		}
	case 4: // truncate a line
		if len(lines[i]) > 1 {
			lines[i] = lines[i][:r.IntN(len(lines[i]))]
		}
	case 5: // truncate the log
		lines = lines[:i]
	case 6: // change a value
		for _, pair := range [][2]string{{`"deny"`, `"allow"`}, {`"allow"`, `"deny"`}, {`"seq":2`, `"seq":9`},
			{`Z"`, `+00:00"`}, {`.002Z"`, `.002000Z"`}, {`"v":"agw-evidence-v2"`, `"v":"agw-evidence-v1"`}} {
			if strings.Contains(lines[i], pair[0]) {
				lines[i] = strings.Replace(lines[i], pair[0], pair[1], 1)
				break
			}
		}
	case 7: // inject whitespace
		lines = append(lines[:i], append([]string{"  "}, lines[i:]...)...)
	case 8: // add a duplicate member
		lines[i] = strings.Replace(lines[i], `{"`, `{"x":1,"x":2,"`, 1)
	case 9: // the edges where JSON and timestamp parsers disagree
		edges := [][2]string{
			{`Z"`, `z"`}, {`.002Z"`, `,002Z"`}, {`Z"`, `+24:00"`}, {`Z"`, `-00:00"`},
			{`Z"`, `+05:30"`}, {`.002Z"`, `.0020000000Z"`}, {`T12:`, `t12:`},
			{`"HTTPStatus":403`, `"HTTPStatus":"403"`}, {`"LatencyMS":1`, `"LatencyMS":1.0`},
			{`"LatencyMS":1`, `"LatencyMS":-0`}, {`"seq":2`, `"seq":"2"`}, {`"seq":`, `"seq":null,"sEq":`},
			{`"v":"agw-evidence-v2"`, `"v":null`}, {`"Federated":false`, `"Federated":null`},
			{`"Federated":false`, `"Federated":0`}, {`"TraceID":""`, `"TraceID":null`},
			{`"count":`, `"count":-`}, {`"keyId":"corpus-key"`, `"keyId":null`},
			{`2026-09-01`, `2026-02-30`}, {`12:00:0`, `24:00:0`}, {`"event":{`, `"event":[{`},
		}
		e := edges[r.IntN(len(edges))]
		lines[i] = strings.Replace(lines[i], e[0], e[1], 1)
	}
	return strings.Join(lines, "\n") + "\n"
}

// TestDifferentialAgainstReference runs thousands of mutated logs through
// this verifier and through `agw audit verify --json` and requires identical
// verdicts, counts and problem lists. It is the strongest available check that
// the two implementations -- and therefore the specification -- agree on
// inputs nobody thought to write a vector for.
func TestDifferentialAgainstReference(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the reference CLI")
	}
	dir := t.TempDir()
	ref := dir + "/agw"
	if out, err := exec.Command("go", "build", "-o", ref, "../agw").CombinedOutput(); err != nil {
		t.Fatalf("build reference: %v\n%s", err, out)
	}

	c := loadCorpus(t)
	keyFile := dir + "/k.pub"
	_ = os.WriteFile(keyFile, []byte(c.PublicKey), 0o644)
	pub, _ := loadKey(keyFile)

	var seeds []string
	for _, v := range c.VerifyVectors {
		seeds = append(seeds, v.Log)
	}

	// 600 keeps `go test` quick; AGW_DIFF_ITERATIONS and AGW_DIFF_SEED run a
	// longer or different search, which CI does on a schedule.
	seed := uint64(20260923)
	if v, err := strconv.ParseUint(os.Getenv("AGW_DIFF_SEED"), 10, 64); err == nil {
		seed = v
	}
	rng := rand.New(rand.NewPCG(seed, 1))
	iterations := 600
	if v, err := strconv.Atoi(os.Getenv("AGW_DIFF_ITERATIONS")); err == nil && v > 0 {
		iterations = v
	}
	for n := 0; n < iterations; n++ {
		log := seeds[rng.IntN(len(seeds))]
		for k := 0; k <= rng.IntN(3); k++ {
			log = mutate(rng, log)
		}
		path := dir + "/m.jsonl"
		_ = os.WriteFile(path, []byte(log), 0o644)

		mine, err := Verify(strings.NewReader(log), pub, nil)
		if err != nil {
			t.Fatal(err)
		}

		out, _ := exec.Command(ref, "audit", "verify", path, "--key", keyFile, "--json").Output()
		var theirs struct {
			Intact            bool   `json:"intact"`
			Records           uint64 `json:"records"`
			Checkpoints       uint64 `json:"checkpoints"`
			HeadSeq           uint64 `json:"head_seq"`
			SignedThrough     uint64 `json:"signed_through"`
			UnanchoredRecords uint64 `json:"unanchored_records"`
			Problems          []struct {
				Seq  uint64 `json:"Seq"`
				Kind string `json:"Kind"`
			} `json:"problems"`
		}
		if err := json.Unmarshal(out, &theirs); err != nil {
			t.Fatalf("iteration %d: reference output not JSON: %v\n%s", n, err, out)
		}

		var a, b []string
		for _, p := range mine.Problems {
			a = append(a, p.Kind+"@"+itoa(p.Seq))
		}
		for _, p := range theirs.Problems {
			b = append(b, p.Kind+"@"+itoa(p.Seq))
		}
		if mine.Intact != theirs.Intact || mine.Records != theirs.Records || mine.Checkpoints != theirs.Checkpoints ||
			mine.HeadSeq != theirs.HeadSeq || mine.SignedThrough != theirs.SignedThrough ||
			mine.UnanchoredRecords != theirs.UnanchoredRecords || strings.Join(a, ",") != strings.Join(b, ",") {
			if out := os.Getenv("AGW_DIFF_OUT"); out != "" {
				_ = os.WriteFile(out, []byte(log), 0o644)
			}
			t.Fatalf("iteration %d: implementations disagree\n agw-verify: intact=%v rec=%d cp=%d head=%d signed=%d un=%d %v\n reference:  intact=%v rec=%d cp=%d head=%d signed=%d un=%d %v\nlog:\n%s",
				n, mine.Intact, mine.Records, mine.Checkpoints, mine.HeadSeq, mine.SignedThrough, mine.UnanchoredRecords, a,
				theirs.Intact, theirs.Records, theirs.Checkpoints, theirs.HeadSeq, theirs.SignedThrough, theirs.UnanchoredRecords, b, log)
		}
	}
}

func itoa(n uint64) string { b, _ := json.Marshal(n); return string(b) }

// TestDifferentialAgainstJavaScript runs the same mutated logs through the
// in-browser verifier (site/assets/rfc0009.js, under Node) and requires it to
// agree with this one. Three implementations written separately from one
// specification, agreeing on inputs nobody wrote a vector for, is the
// evidence that the specification -- not any one program -- defines the format.
func TestDifferentialAgainstJavaScript(t *testing.T) {
	if testing.Short() {
		t.Skip("runs node")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	c := loadCorpus(t)
	dir := t.TempDir()
	keyFile := dir + "/k.pub"
	_ = os.WriteFile(keyFile, []byte(c.PublicKey), 0o644)
	pub, _ := loadKey(keyFile)

	var seeds []string
	for _, v := range c.VerifyVectors {
		seeds = append(seeds, v.Log)
	}
	seed := uint64(20260924)
	if v, err := strconv.ParseUint(os.Getenv("AGW_DIFF_SEED"), 10, 64); err == nil {
		seed = v
	}
	rng := rand.New(rand.NewPCG(seed, 2))
	n := 600
	if v, err := strconv.Atoi(os.Getenv("AGW_DIFF_ITERATIONS")); err == nil && v > 0 {
		n = v
	}

	const batch = 500
	for start := 0; start < n; start += batch {
		var paths, logs []string
		for i := start; i < n && i < start+batch; i++ {
			log := seeds[rng.IntN(len(seeds))]
			for k := 0; k <= rng.IntN(3); k++ {
				log = mutate(rng, log)
			}
			p := fmt.Sprintf("%s/m%05d.jsonl", dir, i)
			_ = os.WriteFile(p, []byte(log), 0o644)
			paths = append(paths, p)
			logs = append(logs, log)
		}
		out, err := exec.Command("node", append([]string{"../../site/test/verify-batch.mjs", keyFile}, paths...)...).Output()
		if err != nil {
			t.Fatalf("node: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) != len(logs) {
			t.Fatalf("node returned %d results for %d logs", len(lines), len(logs))
		}
		for i, line := range lines {
			var js struct {
				Intact            bool     `json:"intact"`
				Records           uint64   `json:"records"`
				Checkpoints       uint64   `json:"checkpoints"`
				HeadSeq           uint64   `json:"head_seq"`
				SignedThrough     uint64   `json:"signed_through"`
				UnanchoredRecords uint64   `json:"unanchored_records"`
				Problems          []string `json:"problems"`
			}
			if err := json.Unmarshal([]byte(line), &js); err != nil {
				t.Fatalf("node output: %v: %s", err, line)
			}
			mine, err := Verify(strings.NewReader(logs[i]), pub, nil)
			if err != nil {
				t.Fatal(err)
			}
			var a []string
			for _, p := range mine.Problems {
				a = append(a, p.Kind+"@"+itoa(p.Seq))
			}
			if mine.Intact != js.Intact || mine.Records != js.Records || mine.Checkpoints != js.Checkpoints ||
				mine.HeadSeq != js.HeadSeq || mine.SignedThrough != js.SignedThrough ||
				mine.UnanchoredRecords != js.UnanchoredRecords || strings.Join(a, ",") != strings.Join(js.Problems, ",") {
				if o := os.Getenv("AGW_DIFF_OUT"); o != "" {
					_ = os.WriteFile(o, []byte(logs[i]), 0o644)
				}
				t.Fatalf("log %d: Go and JavaScript disagree\n go: intact=%v rec=%d cp=%d head=%d signed=%d un=%d %v\n js: %s",
					start+i, mine.Intact, mine.Records, mine.Checkpoints, mine.HeadSeq, mine.SignedThrough,
					mine.UnanchoredRecords, a, line)
			}
		}
	}
}

// TestEmptyLogIsNotCalledVerified: an empty log verifies (nothing in it is
// wrong), but it proves nothing, and deleting every record produces one. So it
// exits 0 and says EMPTY, never VERIFIED (RFC-0009 §6.4).
func TestEmptyLogIsNotCalledVerified(t *testing.T) {
	c := loadCorpus(t)
	dir := t.TempDir()
	keyFile := dir + "/k.pub"
	_ = os.WriteFile(keyFile, []byte(c.PublicKey+"\n"), 0o644)
	for name, content := range map[string]string{"empty": "", "blank lines": "\n  \n\n"} {
		path := dir + "/log.jsonl"
		_ = os.WriteFile(path, []byte(content), 0o644)
		for _, args := range [][]string{{path, "--key", keyFile}, {path}} {
			var out, errb bytes.Buffer
			if got := run(args, &out, &errb); got != 0 {
				t.Errorf("%s %v: exit %d, want 0", name, args[1:], got)
			}
			if !strings.Contains(out.String(), "EMPTY") || strings.Contains(out.String(), "VERIFIED") {
				t.Errorf("%s %v: want EMPTY and no VERIFIED:\n%s", name, args[1:], out.String())
			}
		}
	}
}
