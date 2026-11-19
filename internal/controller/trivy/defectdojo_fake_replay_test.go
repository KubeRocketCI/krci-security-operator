package trivy

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KubeRocketCI/krci-security-operator/internal/ddcontract"
)

// The tests of this file run the scenarios of internal/ddcontract against the fake DefectDojo and compare the
// outcome with the fixtures recorded on a live DefectDojo (make defectdojo-record).

// fakeTarget runs the scenarios against the fake DefectDojo.
type fakeTarget struct {
	*fakeDefectDojo
}

func (f fakeTarget) Triage(_ context.Context, findingID int, triage ddcontract.Triage) error {
	switch triage {
	case ddcontract.TriageFalsePositive:
		f.triage(findingID, statusFalsePositive)
	case ddcontract.TriageOutOfScope:
		f.triage(findingID, statusOutOfScope)
	case ddcontract.TriageRiskAccepted:
		f.triage(findingID, statusRiskAccepted)
	default:
		return fmt.Errorf("no triage state %q", triage)
	}

	return nil
}

// EnableRiskAcceptance does nothing: the fake accepts a risk on every product.
func (f fakeTarget) EnableRiskAcceptance(context.Context, int) error {
	return nil
}

func (f fakeTarget) AddEngagement(_ context.Context, productID int, name string) error {
	f.mu.Lock()
	product, ok := f.products[productID]

	var c ddContext
	if ok {
		c = ddContext{productType: f.productTypes[product.productType], product: product.name, engagement: name}
	}
	f.mu.Unlock()

	if !ok {
		return fmt.Errorf("no product %d", productID)
	}

	f.addEngagement(c)

	return nil
}

func (f fakeTarget) Snapshot(_ context.Context, productType string) (ddcontract.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var s ddcontract.State

	for _, id := range slices.Sorted(maps.Keys(f.products)) {
		p := f.products[id]
		if f.productTypes[p.productType] != productType {
			continue
		}

		s.Products = append(s.Products, ddcontract.ProductState{
			Ref: p.id, Name: p.name, Tags: slices.Clone(p.tags), Engagements: f.engagementStates(p.id),
		})
	}

	return s, nil
}

func (f fakeTarget) engagementStates(productID int) []ddcontract.EngagementState {
	var out []ddcontract.EngagementState

	for _, id := range slices.Sorted(maps.Keys(f.engagements)) {
		e := f.engagements[id]
		if e.product != productID {
			continue
		}

		state := ddcontract.EngagementState{Ref: e.id, Name: e.name}

		for _, testID := range slices.Sorted(maps.Keys(f.tests)) {
			if test := f.tests[testID]; test.engagement == e.id {
				state.Tests = append(state.Tests, f.testState(test))
			}
		}

		out = append(out, state)
	}

	return out
}

func (f fakeTarget) testState(test *ddTest) ddcontract.TestState {
	state := ddcontract.TestState{
		Ref: test.id, Title: test.title, ScanType: test.scanType, Version: test.version, BuildID: test.buildID,
		Tags: slices.Clone(test.tags),
	}

	for _, found := range f.findingsOf(test.id) {
		state.Findings = append(state.Findings, ddcontract.FindingState{
			Ref: found.id, Title: found.title, Severity: found.severity, Service: found.service, Hash: found.hash,
			Active: found.active, Verified: found.verified, Mitigated: found.isMitigated,
			FalsePositive: found.falsePositive, RiskAccepted: found.riskAccepted, OutOfScope: found.outOfScope,
		})
	}

	for _, i := range f.imports {
		if i.test == test.id {
			state.Imports = append(state.Imports, ddcontract.ImportState{
				Ref: i.id, Type: i.kind, Created: i.created, Closed: i.closed, Reactivated: i.reactivated,
				Untouched: i.untouched,
			})
		}
	}

	return state
}

// replay runs the scenario against the fake and returns its differences from the fixture.
func replay(t *testing.T, f *fakeDefectDojo, s ddcontract.Scenario) []string {
	t.Helper()

	fixture, err := ddcontract.LoadFixture(ddcontract.DefaultFixtureDir(), s.Name)
	require.NoError(t, err, "record the fixture with make defectdojo-record")
	require.False(t, fixture.DefectDojo.Deduplication, "the fake does not model deduplication")

	rec, err := ddcontract.NewRunner(fakeTarget{f}, ddcontract.Canonical).Run(context.Background(), s)
	require.NoError(t, err)

	return ddcontract.Compare(fixture.Recording, rec)
}

func TestFakeDefectDojo_ReplaysTheRecordedScenarios(t *testing.T) {
	for _, s := range ddcontract.Scenarios() {
		t.Run(s.Name, func(t *testing.T) {
			if diffs := replay(t, newFakeDefectDojo(), s); len(diffs) > 0 {
				t.Errorf("the fake differs from DefectDojo in %d places:\n%s", len(diffs), strings.Join(diffs, "\n"))
			}
		})
	}
}

func TestFakeDefectDojo_ReplayDetectsADrift(t *testing.T) {
	for _, tc := range []struct {
		name     string
		drift    fakeDrift
		scenario string
		// want is the first difference the replay reports.
		want string
	}{
		{
			name: "the first upload matches entries", drift: fakeDrift{firstUploadMatches: true}, scenario: "repeated-entries",
			want: `step 1 "first reimport of A, A, B": state.products[0].engagements[0].tests[0].findings: recorded`,
		},
		{
			name: "the build_id is written after the findings", drift: fakeDrift{buildIDAfterFindings: true},
			scenario: "failed-first-reimport",
			want: `step 1 "first reimport of invalid JSON with a build_id and tags": ` +
				`state.products[0].engagements[0].tests[0].build_id: recorded "uid:1:aaaa", got ""`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDefectDojo()
			f.drift = tc.drift

			s, ok := ddcontract.ScenarioNamed(tc.scenario)
			require.True(t, ok, "no scenario %q", tc.scenario)

			diffs := replay(t, f, s)

			require.NotEmpty(t, diffs)
			assert.True(t, strings.HasPrefix(diffs[0], tc.want), "first difference: %s", diffs[0])
		})
	}
}
