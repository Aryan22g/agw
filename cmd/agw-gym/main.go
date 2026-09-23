// Command agw-gym runs the confinement plane against a hostile agent in a
// generated environment.
//
// It is not a test suite. A test suite asks whether a function returns what it
// should; this stands up a world, puts an agent in it that is actively trying
// to get out, and reports what got out -- measured by the world's own receipt
// log rather than by the product's account of itself.
//
//	agw-gym run                 one run on a random seed
//	agw-gym run --seed 42       reproduce a specific world
//	agw-gym sweep --runs 50     many seeds, reporting only what breaks
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Aryan22g/agw/internal/gym"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "run":
		err = runOnce(os.Args[2:])
	case "sweep":
		err = runSweep(os.Args[2:])
	case "world":
		err = runWorld(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "score":
		err = runScore(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "agw-gym: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "agw-gym: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `agw-gym -- adversarial environment for the confinement plane

Usage:
  agw-gym run   [--seed N] [--dir PATH] [--json FILE] [--all] [--keep]
  agw-gym sweep [--runs N] [--from-seed N] [--json FILE]

run    Generate one world, run every episode against it, and report.
       The world, its policy and the decoys in it are derived from --seed,
       so a failure is reproducible by passing the seed back.

sweep  Run many seeds and report only the episodes that failed on at least
       one of them. This is what finds the case that only breaks when the
       generator lays the world out a particular way.

The three commands below are the pieces of contained mode, where the agent,
the proxy and the world each run in their own container and the agent has no
route to anything but the proxy. Drive them with gym/contained.sh rather than
by hand.

  agw-gym world --seed N --bind ADDR --control ADDR
                [--write-policy FILE] [--write-hosts FILE --world-addr IP]
  agw-gym agent --seed N --proxy ADDR --out FILE
  agw-gym score --seed N --results FILE --control URL
                --evidence FILE --public-key FILE

Exit status is non-zero when any episode failed, so this fits in CI.
`)
}

func runOnce(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		seed     = fs.Uint64("seed", 0, "world seed (0 picks one at random)")
		dir      = fs.String("dir", "", "working directory for evidence and keys (default: a temp dir)")
		jsonOut  = fs.String("json", "", "also write the full result as JSON")
		showAll  = fs.Bool("all", false, "list every episode, not just the report")
		keep     = fs.Bool("keep", false, "keep the working directory")
		verbose  = fs.Bool("v", false, "log enforcement decisions as they happen")
		boundary = fs.Bool("boundary-enforced", false,
			"assert that the workload genuinely has no route except the proxy")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, workDir, err := execute(*seed, *dir, *verbose, *boundary)
	if err != nil {
		return err
	}
	if !*keep && *dir == "" {
		defer os.RemoveAll(workDir)
	}

	gym.WriteReport(os.Stdout, s)
	if *showAll {
		fmt.Println("EVERY EPISODE")
		gym.WriteAll(os.Stdout, s)
		fmt.Println()
	}
	if *keep || *dir != "" {
		fmt.Printf("evidence and keys kept in %s\n\n", workDir)
	}
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, s); err != nil {
			return err
		}
		fmt.Printf("full result written to %s\n", *jsonOut)
	}

	if s.Failed > 0 {
		os.Exit(1)
	}
	return nil
}

func runSweep(args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	var (
		runs     = fs.Int("runs", 20, "how many seeds to run")
		fromSeed = fs.Uint64("from-seed", 1, "first seed")
		jsonOut  = fs.String("json", "", "write the aggregate as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	type agg struct {
		Episode  string   `json:"episode"`
		Family   string   `json:"family"`
		Severity string   `json:"severity"`
		FailedOn []uint64 `json:"failed_on_seeds"`
		Runs     int      `json:"runs"`
		Detail   string   `json:"example_detail"`
		Goal     string   `json:"goal"`
	}
	failures := make(map[string]*agg)

	var totalEpisodes, totalFailed int
	var escapes, unrecorded int
	var containment float64

	for i := 0; i < *runs; i++ {
		seed := *fromSeed + uint64(i)
		s, workDir, err := execute(seed, "", false, false)
		if err != nil {
			return fmt.Errorf("seed %d: %w", seed, err)
		}
		os.RemoveAll(workDir)

		totalEpisodes += s.Episodes
		totalFailed += s.Failed
		escapes += len(s.CanaryEscapes)
		unrecorded += len(s.UnrecordedEgress)
		containment += s.ContainmentRate

		for _, r := range s.Results {
			if r.Passed {
				continue
			}
			a := failures[r.ID]
			if a == nil {
				a = &agg{Episode: r.ID, Family: string(r.Family), Severity: string(r.Severity), Goal: r.Goal}
				failures[r.ID] = a
			}
			a.FailedOn = append(a.FailedOn, seed)
			a.Runs++
			if a.Detail == "" {
				a.Detail = r.Detail
			}
		}

		fmt.Fprintf(os.Stderr, "\rseed %d  (%d/%d)  failures so far: %d ",
			seed, i+1, *runs, len(failures))
	}
	fmt.Fprintln(os.Stderr)

	list := make([]*agg, 0, len(failures))
	for _, a := range failures {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Runs != list[j].Runs {
			return list[i].Runs > list[j].Runs
		}
		return list[i].Episode < list[j].Episode
	})

	fmt.Printf("\nSWEEP  %d seeds (%d..%d)\n", *runs, *fromSeed, *fromSeed+uint64(*runs)-1)
	fmt.Printf("  episodes run             %d\n", totalEpisodes)
	fmt.Printf("  episode failures         %d\n", totalFailed)
	fmt.Printf("  mean containment rate    %.1f%%\n", 100*containment/float64(*runs))
	fmt.Printf("  secrets that escaped     %d\n", escapes)
	fmt.Printf("  unrecorded egress        %d\n", unrecorded)
	fmt.Printf("  distinct failing episodes %d\n\n", len(list))

	if len(list) == 0 {
		fmt.Println("no episode failed on any seed")
	}
	for _, a := range list {
		fmt.Printf("  %-36s %-18s %-9s failed on %d/%d seeds\n",
			a.Episode, a.Family, a.Severity, a.Runs, *runs)
		fmt.Printf("      %s\n", a.Goal)
		fmt.Printf("      %s\n", a.Detail)
		fmt.Printf("      reproduce: agw-gym run --seed %d\n\n", a.FailedOn[0])
	}

	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, list); err != nil {
			return err
		}
	}
	if totalFailed > 0 {
		os.Exit(1)
	}
	return nil
}

func execute(seed uint64, dir string, verbose, boundary bool) (*gym.Score, string, error) {
	if seed == 0 {
		seed = rand.Uint64()%900000 + 1000
	}
	workDir := dir
	if workDir == "" {
		d, err := os.MkdirTemp("", fmt.Sprintf("agw-gym-%d-*", seed))
		if err != nil {
			return nil, "", err
		}
		workDir = d
	}

	level := slog.LevelError
	if verbose {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	h, err := gym.NewHarness(gym.HarnessConfig{
		Seed:             seed,
		Dir:              workDir,
		Log:              log,
		BoundaryEnforced: boundary,
	})
	if err != nil {
		return nil, workDir, err
	}

	eps := gym.BuildEpisodes(h)
	results, err := gym.Run(h, eps)
	if err != nil {
		h.Close()
		return nil, workDir, err
	}

	// Close before grading: the final checkpoint has to be on disk before the
	// chains are verified, or every chain would read as unpinned at the tail.
	h.Close()

	s, err := gym.Grade(h, results, seed)
	if err != nil {
		return nil, workDir, err
	}
	return s, workDir, nil
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

var _ = strings.TrimSpace

// runWorld hosts the simulated environment for contained mode.
func runWorld(args []string) error {
	fs := flag.NewFlagSet("world", flag.ContinueOnError)
	var (
		seed        = fs.Uint64("seed", 0, "world seed (must match the agent's)")
		bind        = fs.String("bind", "0.0.0.0", "address the world services listen on")
		control     = fs.String("control", "0.0.0.0:9900", "address for the ledger endpoint")
		workload    = fs.String("workload", "agent-eval-01", "workload id the policy is written for")
		writePolicy = fs.String("write-policy", "", "write the generated egress policy here and exit")
		writeHosts  = fs.String("write-hosts", "", "write /etc/hosts lines for the world here and exit")
		worldAddr   = fs.String("world-addr", "", "address the world is reachable at, for --write-hosts")
		subnet      = fs.String("subnet", "127.0.0.0/24",
			"the one narrow CIDR the generated policy exempts, so the world is reachable")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seed == 0 {
		return fmt.Errorf("--seed is required: the agent derives the same topology from it")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The generate-and-exit paths run on the host before any container
	// starts, because the proxy needs its policy and its hosts file at
	// startup. They build the same topology from the same seed without
	// binding anything.
	if *writePolicy != "" || *writeHosts != "" {
		ws, err := gym.NewWorldServerDescribeOnly(*seed, *workload, *subnet, log)
		if err != nil {
			return err
		}
		if *writePolicy != "" {
			if err := ws.WritePolicy(*writePolicy); err != nil {
				return err
			}
			fmt.Printf("egress policy written to %s\n", *writePolicy)
		}
		if *writeHosts != "" {
			if *worldAddr == "" {
				return fmt.Errorf("--write-hosts needs --world-addr")
			}
			if err := ws.WriteHosts(*writeHosts, *worldAddr); err != nil {
				return err
			}
			fmt.Printf("hosts file written to %s\n", *writeHosts)
		}
		return nil
	}

	ws, err := gym.NewWorldServer(*seed, *workload, *bind, *subnet, log)
	if err != nil {
		return err
	}
	for _, s := range ws.World.Services {
		log.Info("service up", slog.String("name", s.Name), slog.String("host", s.Hostname),
			slog.Int("port", s.Port), slog.Bool("in_policy", s.InPolicy))
	}
	return ws.ServeControl(*control)
}

// runAgent is the hostile workload in contained mode.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	var (
		seed     = fs.Uint64("seed", 0, "world seed (must match the world's)")
		proxy    = fs.String("proxy", "", "the confinement proxy, host:port")
		workload = fs.String("workload", "agent-eval-01", "this workload's id")
		out      = fs.String("out", "results.json", "write episode results here")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seed == 0 || *proxy == "" {
		return fmt.Errorf("--seed and --proxy are required")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	h, err := gym.NewRemoteHarness(*seed, *workload, *proxy, log)
	if err != nil {
		return err
	}
	eps := gym.BuildEpisodes(h)
	results, err := gym.Run(h, eps)
	if err != nil {
		return err
	}
	if err := writeJSON(*out, results); err != nil {
		return err
	}

	var ran, failed int
	for _, r := range results {
		if r.Outcome == "skipped" {
			continue
		}
		ran++
		if !r.Passed {
			failed++
		}
	}
	fmt.Printf("agent finished: %d episodes ran, %d failed (%d skipped)\n",
		ran, failed, len(results)-ran)
	return nil
}

// runScore grades a contained run from artefacts produced in three different
// containers, none of which is trusted about the others.
func runScore(args []string) error {
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	var (
		seed     = fs.Uint64("seed", 0, "world seed")
		workload = fs.String("workload", "agent-eval-01", "workload id")
		resPath  = fs.String("results", "", "episode results written by `agw-gym agent`")
		control  = fs.String("control", "", "the world's control URL, e.g. http://127.0.0.1:9900")
		evidence = fs.String("evidence", "", "the evidence chain the proxy wrote")
		pubKey   = fs.String("public-key", "", "the checkpoint public key")
		jsonOut  = fs.String("json", "", "also write the full result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"--results": *resPath, "--control": *control,
		"--evidence": *evidence, "--public-key": *pubKey,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if *seed == 0 {
		return fmt.Errorf("--seed is required")
	}

	var results []gym.Result
	raw, err := os.ReadFile(*resPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &results); err != nil {
		return fmt.Errorf("parse %s: %w", *resPath, err)
	}

	hits, err := gym.FetchLedger(*control)
	if err != nil {
		return fmt.Errorf("read the world's receipt log: %w", err)
	}
	canaries, err := gym.FetchCanaries(*control)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h, err := gym.NewRemoteHarness(*seed, *workload, "unused", log)
	if err != nil {
		return err
	}

	s, err := gym.GradeContained(h, results, *seed, hits, canaries, *evidence, *pubKey)
	if err != nil {
		return err
	}

	gym.WriteReport(os.Stdout, s)
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, s); err != nil {
			return err
		}
	}
	if s.Failed > 0 {
		os.Exit(1)
	}
	return nil
}
