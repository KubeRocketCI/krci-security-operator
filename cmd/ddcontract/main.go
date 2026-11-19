// Command ddcontract runs the DefectDojo contract scenarios against a live DefectDojo: it records the fixtures of
// the fake DefectDojo, or verifies them and reports every difference.
//
// The token is read from DEFECTDOJO_TOKEN; it needs to create and delete product types. Every scenario runs under
// its own product type, deleted afterwards unless -keep is set.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/KubeRocketCI/krci-security-operator/internal/ddcontract"
)

const (
	modeRecord = "record"
	modeVerify = "verify"
)

type options struct {
	mode      string
	url       string
	apiToken  string
	dir       string
	scenarios []string
	keep      bool
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err = run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		stop()
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var (
		opts      options
		scenarios string
	)

	fs := flag.NewFlagSet("ddcontract", flag.ContinueOnError)
	fs.StringVar(&opts.mode, "mode", modeVerify, "record: write the fixtures; verify: compare them with the live answers")
	fs.StringVar(&opts.url, "url", os.Getenv("DEFECTDOJO_URL"), "DefectDojo base URL (default $DEFECTDOJO_URL)")
	fs.StringVar(&opts.dir, "dir", ddcontract.DefaultFixtureDir(), "fixtures directory")
	fs.StringVar(&scenarios, "scenarios", "", "comma-separated scenario names (default every scenario)")
	fs.BoolVar(&opts.keep, "keep", false, "keep the product type of each scenario")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}

	opts.apiToken = os.Getenv("DEFECTDOJO_TOKEN")

	switch {
	case opts.mode != modeRecord && opts.mode != modeVerify:
		return opts, fmt.Errorf("-mode is %q, want %s or %s", opts.mode, modeRecord, modeVerify)
	case opts.url == "":
		return opts, errors.New("set -url or DEFECTDOJO_URL")
	case opts.apiToken == "":
		return opts, errors.New("set DEFECTDOJO_TOKEN")
	}

	if scenarios != "" {
		opts.scenarios = strings.Split(scenarios, ",")
	}

	return opts, nil
}

func run(ctx context.Context, opts options) error {
	selected, err := selectScenarios(opts.scenarios)
	if err != nil {
		return err
	}

	server, err := ddcontract.NewLive(opts.url, opts.apiToken, "").ServerInfo(ctx)
	if err != nil {
		return fmt.Errorf("read the DefectDojo version: %w", err)
	}

	fmt.Printf("DefectDojo %s, deduplication %t\n", server.Version, server.Deduplication)

	if err = server.Check(); err != nil {
		return err
	}

	failed := 0

	for _, s := range selected {
		if err = ctx.Err(); err != nil {
			return fmt.Errorf("stopped before scenario %s: %w", s.Name, err)
		}

		if !runScenario(ctx, opts, server, s) {
			failed++
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d scenarios failed", failed, len(selected))
	}

	return nil
}

func selectScenarios(names []string) ([]ddcontract.Scenario, error) {
	if len(names) == 0 {
		return ddcontract.Scenarios(), nil
	}

	out := make([]ddcontract.Scenario, 0, len(names))

	for _, name := range names {
		s, ok := ddcontract.ScenarioNamed(name)
		if !ok {
			return nil, fmt.Errorf("no scenario %q", name)
		}

		out = append(out, s)
	}

	return out, nil
}

// runScenario runs the scenario under a new product type and records or verifies it; false when it failed.
func runScenario(ctx context.Context, opts options, server ddcontract.Server, s ddcontract.Scenario) bool {
	run, err := runName()
	if err != nil {
		return fail(s.Name, err)
	}

	live := ddcontract.NewLive(opts.url, opts.apiToken, run)

	rec, err := ddcontract.NewRunner(live, run).Run(ctx, s)
	cleanup(ctx, opts, live, run)

	if err != nil {
		return fail(s.Name, err)
	}

	if opts.mode == modeRecord {
		return record(opts.dir, server, rec)
	}

	return verify(opts.dir, server, rec)
}

func cleanup(ctx context.Context, opts options, live *ddcontract.Live, run string) {
	if opts.keep {
		fmt.Printf("kept product type %s\n", run)

		return
	}

	if err := live.DeleteProductType(context.WithoutCancel(ctx), run); err != nil {
		fmt.Printf("could not delete product type %s: %v\n", run, err)
	}
}

func record(dir string, server ddcontract.Server, rec ddcontract.Recording) bool {
	if err := ddcontract.WriteFixture(dir, ddcontract.Fixture{DefectDojo: server, Recording: rec}); err != nil {
		return fail(rec.Scenario, err)
	}

	fmt.Printf("recorded %s: %d steps\n", rec.Scenario, len(rec.Steps))

	return true
}

func verify(dir string, server ddcontract.Server, rec ddcontract.Recording) bool {
	fixture, err := ddcontract.LoadFixture(dir, rec.Scenario)
	if err != nil {
		return fail(rec.Scenario, err)
	}

	if fixture.DefectDojo != server {
		fmt.Printf("note %s: recorded on DefectDojo %s, deduplication %t\n", rec.Scenario, fixture.DefectDojo.Version,
			fixture.DefectDojo.Deduplication)
	}

	diffs := ddcontract.Compare(fixture.Recording, rec)
	if len(diffs) == 0 {
		fmt.Printf("ok %s\n", rec.Scenario)

		return true
	}

	fmt.Printf("FAIL %s: %d differences from the fixture\n", rec.Scenario, len(diffs))

	for _, d := range diffs {
		fmt.Println("  " + d)
	}

	return false
}

// fail prints the failure of the scenario and returns false.
func fail(scenario string, err error) bool {
	fmt.Printf("FAIL %s: %v\n", scenario, err)

	return false
}

// runName names one scenario run: its product type and cluster name.
func runName() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate a run name: %w", err)
	}

	return ddcontract.Canonical + "-" + hex.EncodeToString(b), nil
}
