package ddcontract

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayRequests_TheClientSendsTheRecordedRequests(t *testing.T) {
	for _, s := range Scenarios() {
		t.Run(s.Name, func(t *testing.T) {
			fixture, err := LoadFixture(DefaultFixtureDir(), s.Name)
			require.NoError(t, err, "record it with make defectdojo-record")

			diffs, err := ReplayRequests(context.Background(), s, fixture)
			require.NoError(t, err)

			if len(diffs) > 0 {
				t.Errorf("the client sends other requests than recorded in %d places:\n%s", len(diffs),
					strings.Join(diffs, "\n"))
			}
		})
	}
}

func TestReplayRequests_ReportsAChangedFormFieldAndBody(t *testing.T) {
	fixture, err := LoadFixture(DefaultFixtureDir(), "build-id")
	require.NoError(t, err)

	first := &fixture.Steps[0].Exchanges[0]
	require.Equal(t, "/api/v2/reimport-scan/", first.Path)

	for i, field := range first.Form {
		if field[0] == "minimum_severity" {
			first.Form[i][1] = "Low"
		}
	}

	step := slices.IndexFunc(fixture.Steps, func(s StepRecord) bool { return s.Name == "set the build_id" })
	require.GreaterOrEqual(t, step, 0)

	setBuildID := &fixture.Steps[step].Exchanges[len(fixture.Steps[step].Exchanges)-1]
	require.Equal(t, "PATCH", setBuildID.Method)
	setBuildID.Body = []byte(`{"build_id":"uid:9:zzzz"}`)

	s, ok := ScenarioNamed("build-id")
	require.True(t, ok)

	diffs, err := ReplayRequests(context.Background(), s, fixture)
	require.NoError(t, err)

	assert.Equal(t, []string{
		`step 1 "first reimport of A with a build_id": request 1 POST /api/v2/reimport-scan/: form: ` +
			`recorded minimum_severity=Low, got minimum_severity=Info`,
		fmt.Sprintf(`step %d "set the build_id": request 1 PATCH /api/v2/tests/{id}/: body: `, step+1) +
			`recorded {"build_id":"uid:9:zzzz"}, got {"build_id":"uid:3:cccc"}`,
	}, diffs)
}

func TestReplayRequests_ReportsAMissingAnswerAndAChangedPathInTheirStepOnly(t *testing.T) {
	fixture, err := LoadFixture(DefaultFixtureDir(), "build-id")
	require.NoError(t, err)

	list := &fixture.Steps[1]
	require.Equal(t, "list the tests", list.Name)
	require.Len(t, list.Exchanges, 4)
	list.Exchanges = list.Exchanges[:3]

	reimport := &fixture.Steps[2].Exchanges[0]
	reimport.Path = "/api/v2/import-scan/"

	s, ok := ScenarioNamed("build-id")
	require.True(t, ok)

	diffs, err := ReplayRequests(context.Background(), s, fixture)
	require.NoError(t, err)

	assert.Equal(t, []string{
		`step 2 "list the tests": request 4 GET /api/v2/tests/?engagement={id}&limit=100&offset=0` +
			`&scan_type=Trivy+Operator+Scan: not recorded`,
		`step 3 "reimport A with another build_id in spaces": request 1 POST /api/v2/import-scan/: ` +
			`sent POST /api/v2/reimport-scan/`,
	}, diffs, "the other steps get their own answers")
}
