// Package auditcli is the evidence command line: verify, show, tail, export
// and verify-bundle.
//
// It lives here rather than in either binary because both binaries need it.
// An operator running `agw` and an auditor running `ags` are looking at the
// same evidence, and two copies of these commands had already drifted: the
// usage text `agw` printed told users to run a verify invocation that `ags`
// did not accept. One implementation means one set of flags.
package auditcli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Aryan22g/agw/internal/aat"
	"github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// ExitError carries a process exit status out of a command without the
// command calling os.Exit, so it stays testable.
//
// Status 2 means "the evidence did not verify", distinct from 1 ("the command
// could not run"). A script gating a release on verification needs to tell
// those apart: one is a finding, the other is a broken pipeline.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// Out is where commands write their report. Replaceable for tests.
var Out io.Writer = os.Stdout

// Run dispatches an audit subcommand. prog is the binary name, used in usage
// and in the follow-up commands printed to the user.
func Run(prog string, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(prog)
		return nil
	}
	switch args[0] {
	case "verify":
		return Verify(prog, args[1:])
	case "show":
		return Show(prog, args[1:])
	case "tail":
		return Show(prog, append([]string{"--follow"}, args[1:]...))
	case "export":
		return Export(prog, args[1:])
	case "verify-bundle":
		return VerifyBundle(prog, args[1:])
	default:
		return fmt.Errorf("unknown audit subcommand %q (want verify, show, tail, export or verify-bundle)", args[0])
	}
}

func usage(prog string) {
	fmt.Fprintf(os.Stderr, `%[1]s audit -- work with evidence

  %[1]s audit verify  EVIDENCE.jsonl --key checkpoint.pub [--anchor kept-checkpoint.json]
  %[1]s audit show    EVIDENCE.jsonl [--agent ID] [--decision deny] [--would-deny] [--since 1h]
  %[1]s audit tail    EVIDENCE.jsonl [--agent ID]
  %[1]s audit export  EVIDENCE.jsonl --out bundle.json [--key checkpoint.pub] [--from T] [--to T]
  %[1]s audit verify-bundle bundle.json --key checkpoint.pub

--key accepts a public key file or the base64 key itself.
Verification needs only the file and the key: no network, no account.
`, prog)
}

// newFlags builds a flag set whose errors come back as values rather than
// terminating the process.
func newFlags(prog, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(prog+" audit "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parse accepts flags before, after or around positional arguments.
//
// The standard library stops at the first positional, which turns
// `verify evidence.jsonl --key k.pub` -- the order people actually type --
// into "unknown argument --key". Re-parsing after each positional removes
// that trap without inventing a flag syntax.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// pathArg resolves the evidence path from a flag or the first positional.
func pathArg(flagVal string, positional []string, what string) (string, error) {
	switch {
	case flagVal != "" && len(positional) > 0 && positional[0] != flagVal:
		return "", fmt.Errorf("%s given twice (%q and %q)", what, flagVal, positional[0])
	case flagVal != "":
		return flagVal, nil
	case len(positional) > 0:
		return positional[0], nil
	default:
		return "", fmt.Errorf("an %s path is required", what)
	}
}

// LoadPublicKey accepts either a path to a key file or the base64 key itself.
//
// Both forms appear in the wild -- `agw keygen` writes a file, and the older
// docs passed the value -- and guessing wrong produced "illegal base64 data at
// input byte 52", which told nobody what to do. A path that exists is read;
// anything else is decoded as a key.
func LoadPublicKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	if info, err := os.Stat(v); err == nil && !info.IsDir() {
		raw, err := os.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("read public key %s: %w", v, err)
		}
		pub, err := keys.DecodePublicKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("%s does not contain an Ed25519 public key: %w", v, err)
		}
		return pub, nil
	}
	pub, err := keys.DecodePublicKey(v)
	if err != nil {
		if strings.ContainsAny(v, "/\\") || strings.HasSuffix(v, ".pub") {
			return nil, fmt.Errorf("public key file %s does not exist", v)
		}
		return nil, fmt.Errorf("--key is neither a readable file nor a base64 Ed25519 public key: %w", err)
	}
	return pub, nil
}

// keyFlags registers --key with --public-key as an alias, so every older
// invocation keeps working.
func keyFlags(fs *flag.FlagSet) *string {
	v := new(string)
	fs.StringVar(v, "key", "", "checkpoint public key: a file, or the base64 key")
	fs.StringVar(v, "public-key", "", "alias for --key")
	return v
}

// Verify checks an evidence log's integrity.
//
// This is the command an auditor runs. It reads only the log file and a
// public key, and talks to nothing: evidence that can only be verified by the
// party that produced it is not evidence.
func Verify(prog string, args []string) error {
	fs := newFlags(prog, "verify")
	var (
		logPath = fs.String("log", "", "path to the evidence log (or give it as an argument)")
		pubKey  = keyFlags(fs)
		quiet   = fs.Bool("quiet", false, "print only the verdict")
		asJSON  = fs.Bool("json", false, "print the result as JSON")
		anchor  = fs.String("anchor", "",
			"a checkpoint line kept out of band; proves the log was not rolled back to an earlier one")
	)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	path, err := pathArg(*logPath, pos, "evidence log")
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	defer f.Close()

	pub, err := LoadPublicKey(*pubKey)
	if err != nil {
		return err
	}

	// A checkpoint the auditor kept elsewhere is the only thing that can
	// detect a log truncated exactly at a checkpoint boundary: that edit
	// leaves a shorter log in which everything still verifies.
	var anchorCP *audit.Checkpoint
	if *anchor != "" {
		cp, err := ReadAnchor(*anchor)
		if err != nil {
			return err
		}
		anchorCP = cp
	}

	res, problems, err := audit.VerifyWithAnchor(f, pub, anchorCP)
	if err != nil {
		return err
	}

	if *asJSON {
		out := map[string]any{
			"log": path, "intact": res.Intact, "records": res.Records,
			"checkpoints": res.Checkpoints, "head_seq": res.HeadSeq, "head_hash": res.HeadHash,
			"signatures_checked": pub != nil, "signed_through": res.SignedThrough,
			"unanchored_records": res.UnanchoredRecords, "problems": problems,
		}
		enc := json.NewEncoder(Out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		if !res.Intact {
			return &ExitError{Code: 2, Msg: fmt.Sprintf("%d verification problem(s)", len(problems))}
		}
		return nil
	}

	p := func(format string, a ...any) { fmt.Fprintf(Out, format, a...) }

	if !*quiet {
		p("Evidence log: %s\n\n", path)
		p("  records           %d\n", res.Records)
		p("  checkpoints       %d\n", res.Checkpoints)
		if res.Records > 0 {
			p("  covering          %s → %s\n",
				res.FirstAt.Format(time.RFC3339), res.LastAt.Format(time.RFC3339))
		}
		p("  chain head        %s (seq %d)\n", shortHash(res.HeadHash), res.HeadSeq)

		if pub == nil {
			p("  signatures        not checked (no --key given)\n")
		} else {
			p("  signed through    seq %d\n", res.SignedThrough)
			if res.UnanchoredRecords > 0 {
				p("                    %d record(s) after the last checkpoint are chained\n", res.UnanchoredRecords)
				p("                    but not pinned by any signature, so they are the\n")
				p("                    records an attacker could remove undetectably\n")
			}
		}
		if anchorCP != nil {
			p("  anchor            seq %d %s\n", anchorCP.Seq, shortHash(anchorCP.Hash))
		} else if pub != nil {
			p("  anchor            none given (--anchor detects rollback to an earlier checkpoint)\n")
		}
		p("\n")
	}

	if res.Intact {
		switch {
		case res.Records == 0:
			// Nothing was checked, and an empty file is exactly what deleting
			// every record leaves behind. "VERIFIED" would read as assurance.
			p("EMPTY — the log contains no records, so there is nothing to verify.\n")
			p("An empty log is also what deleting every record produces; only a\n")
			p("checkpoint kept from an earlier reading (--anchor) tells the two apart.\n")
		case pub == nil:
			p("VERIFIED (chain only) — no record was altered, removed or reordered.\n")
			p("Supply --key to also prove the log was not rewritten wholesale.\n")
		case res.UnanchoredRecords > 0:
			// Saying "VERIFIED" flat would overstate it: the tail is exactly
			// what an attacker can delete without leaving a trace, so the
			// verdict names how far the proof actually reaches.
			p("VERIFIED THROUGH seq %d — every record up to there was signed by the\n", res.SignedThrough)
			p("holder of the given key. The %d record(s) after it are chained but not\n", res.UnanchoredRecords)
			p("signed; removing them would leave a log that still verifies.\n")
		default:
			p("VERIFIED — no record was altered, removed or reordered, and every\n")
			p("record is covered by a checkpoint signed with the given key.\n")
		}
		return nil
	}

	if onlyUnanchored(problems) {
		// Nothing contradicts anything: the log is simply not signed. That is
		// what a log cut off before its first checkpoint looks like, and also
		// what one rewritten wholesale looks like -- so it proves nothing, and
		// fails, but calling it tampering would accuse without evidence.
		p("NOT VERIFIED — nothing in this log is signed (it has no checkpoint).\n")
		p("Its records are consistent with each other, but without a signature they\n")
		p("could have been rewritten together. Ask for the log once it has been\n")
		p("checkpointed.\n")
		return &ExitError{Code: 2, Msg: "evidence is not signed"}
	}
	p("TAMPERING DETECTED — %d problem(s):\n\n", len(problems))
	for _, pr := range problems {
		p("  seq %-8d %-14s %s\n", pr.Seq, pr.Kind, pr.Detail)
	}
	p("\nRecords before the first problem remain trustworthy.\n")
	return &ExitError{Code: 2, Msg: "evidence did not verify"}
}

// ReadAnchor loads a single checkpoint line an auditor kept out of band.
//
// It takes the checkpoint as it was written, rather than a seq/hash pair on
// the command line, so that what the auditor stores is a line copied verbatim
// out of a log they once verified -- not two values they have to transcribe
// correctly under pressure. Given a whole evidence log, it takes the LAST
// checkpoint, which is what "keep a copy of today's log" should mean.
func ReadAnchor(path string) (*audit.Checkpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read anchor: %w", err)
	}
	var last *audit.Checkpoint
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var cp audit.Checkpoint
		if err := json.Unmarshal([]byte(line), &cp); err != nil {
			continue
		}
		if cp.Type == "checkpoint" {
			c := cp
			last = &c
		}
	}
	if last == nil {
		return nil, fmt.Errorf("anchor %s contains no checkpoint line", path)
	}
	return last, nil
}

// parseSince accepts an RFC3339 time or a duration back from now ("90m",
// "24h"). At 03:00 nobody types a timestamp.
func parseSince(v string, now time.Time) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since %q is neither a duration (90m, 24h) nor an RFC3339 time", v)
	}
	return t, nil
}

type showFilter struct {
	tenant, agent, action, decision, reason string
	since                                   time.Time
}

func (f showFilter) match(rec audit.Record) bool {
	e := rec.Event
	switch {
	case f.tenant != "" && e.TenantID != f.tenant:
	case f.agent != "" && e.AgentID != f.agent:
	case f.action != "" && !strings.HasPrefix(e.Action, f.action):
	case f.decision != "" && e.Decision != f.decision:
	case f.reason != "" && e.ReasonCode != f.reason:
	case !f.since.IsZero() && rec.Timestamp.Before(f.since):
	default:
		return true
	}
	return false
}

// Show prints decisions from an evidence log, filtered, optionally following
// it as it grows.
//
// The query an investigator actually arrives with is "what did this agent do,
// and when", so that is the shape of the filters.
func Show(prog string, args []string) error {
	fs := newFlags(prog, "show")
	var (
		logPath   = fs.String("log", "", "path to the evidence log (or give it as an argument)")
		tenant    = fs.String("tenant", "", "filter by tenant id")
		agent     = fs.String("agent", "", "filter by agent id")
		action    = fs.String("action", "", "filter by action (prefix match)")
		decision  = fs.String("decision", "", "filter by decision: allow, deny, error, would_deny, would_allow")
		reason    = fs.String("reason", "", "filter by reason code, e.g. metadata_endpoint")
		wouldDeny = fs.Bool("would-deny", false, "only what shadow-mode policy would have denied")
		denied    = fs.Bool("denied", false, "only refusals")
		since     = fs.String("since", "", "only records since a time (RFC3339) or duration ago (90m, 24h)")
		asJSON    = fs.Bool("json", false, "emit matching records as JSON lines")
		followF   = fs.Bool("follow", false, "keep reading as records are appended (like tail -f)")
	)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	path, err := pathArg(*logPath, pos, "evidence log")
	if err != nil {
		return err
	}

	filter := showFilter{tenant: *tenant, agent: *agent, action: *action, decision: *decision, reason: *reason}
	if *wouldDeny {
		filter.decision = "would_deny"
	}
	if *denied {
		filter.decision = "deny"
	}
	if filter.since, err = parseSince(*since, time.Now()); err != nil {
		return err
	}

	print := func(rec audit.Record) {
		if *asJSON {
			out, _ := json.Marshal(rec)
			fmt.Fprintln(Out, string(out))
			return
		}
		e := rec.Event
		verdict := e.Decision
		if e.ReasonCode != "" && e.ReasonCode != "allowed" {
			verdict = e.Decision + "/" + e.ReasonCode
		}
		target := e.ResourceID
		if target == "" {
			target = e.Action
		}
		fmt.Fprintf(Out, "%-19s  %-6d  %-32s  %-18s  %-28s  %s\n",
			rec.Timestamp.Local().Format("2006-01-02 15:04:05"), rec.Seq,
			truncate(verdict, 32), truncate(e.Action, 18), truncate(target, 28), e.AgentID)
	}

	if !*asJSON {
		fmt.Fprintf(Out, "%-19s  %-6s  %-32s  %-18s  %-28s  %s\n",
			"TIME", "SEQ", "DECISION", "ACTION", "TARGET", "AGENT")
	}

	if *followF {
		return follow(path, filter, print)
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	defer f.Close()

	records, err := audit.ReadRecords(f)
	if err != nil {
		return err
	}

	var shown int
	for _, rec := range records {
		if !filter.match(rec) {
			continue
		}
		shown++
		print(rec)
	}

	if !*asJSON {
		fmt.Fprintf(Out, "\n%d of %d record(s) matched.\n", shown, len(records))
		if shown == 0 && len(records) > 0 && filter.decision == "would_deny" {
			fmt.Fprintf(Out, "(would_deny records exist only when the recorder ran with --policy)\n")
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:16] + "…"
}

// Export packages evidence for an auditor.
func Export(prog string, args []string) error {
	fs := newFlags(prog, "export")
	var (
		logPath = fs.String("log", "", "path to the evidence log (or give it as an argument)")
		out     = fs.String("out", "", "output bundle path (default: stdout)")
		pubKey  = keyFlags(fs)
		keyID   = fs.String("key-id", "", "key id to record in the bundle")
		tenant  = fs.String("tenant", "", "filter by tenant id")
		agent   = fs.String("agent", "", "filter by agent id")
		from    = fs.String("from", "", "only records at or after this RFC3339 time")
		to      = fs.String("to", "", "only records at or before this RFC3339 time")
		format  = fs.String("format", "bundle", "bundle (agw evidence bundle) or aat (IETF agent-audit-trail-04 JSON Lines)")
		agentV  = fs.String("agent-version", "", "aat: the agents' SemVer, which the chain does not record (default 0.0.0)")
	)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	path, err := pathArg(*logPath, pos, "evidence log")
	if err != nil {
		return err
	}

	switch *format {
	case "bundle":
	case "aat":
		if *tenant != "" || *agent != "" || *from != "" || *to != "" {
			return fmt.Errorf("--format aat converts a whole chain; filters would break its prev_hash links")
		}
		return exportAAT(prog, path, *pubKey, *agentV, *out)
	default:
		return fmt.Errorf("--format %q: want bundle or aat", *format)
	}

	filter := audit.ExportFilter{TenantID: *tenant, AgentID: *agent}
	if *from != "" {
		t, err := time.Parse(time.RFC3339, *from)
		if err != nil {
			return fmt.Errorf("parse --from: %w", err)
		}
		filter.From = t
	}
	if *to != "" {
		t, err := time.Parse(time.RFC3339, *to)
		if err != nil {
			return fmt.Errorf("parse --to: %w", err)
		}
		filter.To = t
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	defer f.Close()

	pub, err := LoadPublicKey(*pubKey)
	if err != nil {
		return err
	}

	bundle, err := audit.Export(f, pub, *keyID, filter, time.Now().UTC())
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if *out == "" {
		_, err = Out.Write(data)
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}

	p := func(format string, a ...any) { fmt.Fprintf(Out, format, a...) }
	p("Evidence bundle written to %s\n\n", *out)
	p("  records      %d (seq %d..%d)\n",
		len(bundle.Records), bundle.Continuity.FirstSeq, bundle.Continuity.LastSeq)
	p("  checkpoints  %d\n", len(bundle.Checkpoints))
	if bundle.Continuity.Complete {
		p("  contiguous   yes -- a removed record would be detectable\n")
	} else {
		p("  contiguous   NO (filtered) -- omissions cannot be detected\n")
		p("               from this file alone; export unfiltered to check\n")
	}
	p("\nThe recipient verifies with:\n")
	p("  %s audit verify-bundle %s --key <checkpoint public key>\n", prog, *out)
	return nil
}

// VerifyBundle checks an exported bundle.
func VerifyBundle(prog string, args []string) error {
	fs := newFlags(prog, "verify-bundle")
	var (
		bundlePath = fs.String("bundle", "", "path to the evidence bundle (or give it as an argument)")
		pubKey     = keyFlags(fs)
	)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	path, err := pathArg(*bundlePath, pos, "evidence bundle")
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	var bundle audit.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	pub, err := LoadPublicKey(*pubKey)
	if err != nil {
		return err
	}

	problems, err := audit.VerifyBundle(&bundle, pub)
	if err != nil {
		return err
	}

	p := func(format string, a ...any) { fmt.Fprintf(Out, format, a...) }
	p("Evidence bundle: %s\n\n", path)
	p("  subject      tenant=%s agent=%s\n", orDash(bundle.Subject.TenantID), orDash(bundle.Subject.AgentID))
	p("  exported     %s\n", bundle.Subject.ExportedAt.Format(time.RFC3339))
	p("  records      %d (seq %d..%d)\n",
		len(bundle.Records), bundle.Continuity.FirstSeq, bundle.Continuity.LastSeq)
	p("  checkpoints  %d\n", len(bundle.Checkpoints))
	p("  contiguous   %v\n\n", bundle.Continuity.Complete)

	if len(problems) > 0 {
		p("TAMPERING DETECTED -- %d problem(s):\n\n", len(problems))
		for _, pr := range problems {
			p("  seq %-8d %-12s %s\n", pr.Seq, pr.Kind, pr.Detail)
		}
		return &ExitError{Code: 2, Msg: "bundle did not verify"}
	}

	switch {
	case len(bundle.Records) == 0:
		p("EMPTY -- the bundle contains no records, so there is nothing to verify.\n")
	case pub == nil:
		p("VERIFIED (content only) -- no record was altered.\n")
		p("Supply --key to also verify the checkpoint signatures.\n")
	case bundle.Continuity.Complete:
		p("VERIFIED -- no record was altered or removed, and every\n")
		p("checkpoint was signed by the holder of the given key.\n")
	default:
		p("VERIFIED (filtered extract) -- no record present was altered,\n")
		p("and every checkpoint verifies. Because this extract is filtered,\n")
		p("omission of an excluded record cannot be ruled out from this\n")
		p("file alone; request an unfiltered export to check.\n")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "(any)"
	}
	return s
}

// exportAAT converts a verified chain to draft-sharif-agent-audit-trail-04.
func exportAAT(prog, path, keyArg, agentVersion, out string) error {
	pub, err := LoadPublicKey(keyArg)
	if err != nil {
		return err
	}
	if pub == nil {
		// Converting what has not been verified against its signatures would
		// give an unsigned rewrite the appearance of an attested export.
		return fmt.Errorf("--format aat needs --key: the chain is verified against its signatures before it is converted")
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	res, problems, err := audit.Verify(f, pub)
	f.Close()
	if err != nil {
		return err
	}
	if !res.Intact {
		fmt.Fprintf(os.Stderr, "the evidence does not verify (%d problem(s)); run `%s audit verify` to see them\n",
			len(problems), prog)
		return &ExitError{Code: 2, Msg: "refusing to convert evidence that does not verify"}
	}

	f, err = os.Open(path)
	if err != nil {
		return err
	}
	records, err := audit.ReadRecords(f)
	f.Close()
	if err != nil {
		return err
	}

	converted, err := aat.Convert(records, res, aat.Options{AgentVersion: agentVersion, Source: filepath.Base(path)})
	if err != nil {
		return err
	}
	data, err := aat.Marshal(converted)
	if err != nil {
		return err
	}
	// Hold the output to the draft's own verifier rules before handing it
	// to anyone. A conversion bug should fail here, not in their tooling.
	if errs := aat.Check(bytes.NewReader(data)); len(errs) > 0 {
		return fmt.Errorf("internal error: the AAT export fails the draft's checks: %v", errs[0])
	}

	if out == "" {
		_, err = Out.Write(data)
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(Out, "%d evidence records -> %d %s records in %s\n",
		len(records), len(converted), aat.DraftVersion, out)
	fmt.Fprintf(Out, "The source chain verified before conversion (signed through seq %d).\n", res.SignedThrough)
	if res.UnanchoredRecords > 0 {
		fmt.Fprintf(Out, "Note: %d record(s) after seq %d were not covered by a checkpoint.\n",
			res.UnanchoredRecords, res.SignedThrough)
	}
	fmt.Fprintf(Out, "The AAT file is unsigned; keep it with %s, whose checkpoints are the integrity evidence.\n", path)
	return nil
}

// onlyUnanchored reports whether every problem is the log's lack of a checkpoint.
func onlyUnanchored(problems []audit.VerifyProblem) bool {
	for _, p := range problems {
		if p.Kind != "unanchored" {
			return false
		}
	}
	return len(problems) > 0
}
