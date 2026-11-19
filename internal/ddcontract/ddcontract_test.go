package ddcontract

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recording(steps ...StepRecord) Recording {
	return Recording{Scenario: "s", Steps: steps}
}

func finding(ref int, active bool) FindingState {
	return FindingState{Ref: ref, Title: "cve-1 libssl 3.0.0", Active: active}
}

func stateWith(findings ...FindingState) State {
	return State{Products: []ProductState{{Ref: 1, Name: "ddcontract/ns", Tags: []string{}, Engagements: []EngagementState{{
		Ref: 1, Name: "trivy-operator", Tests: []TestState{{Ref: 1, Findings: findings}},
	}}}}}
}

func TestCompare_ReportsEveryDifferenceByPathAndIgnoresExchanges(t *testing.T) {
	recorded := recording(StepRecord{
		Name: "reimport", Result: Result{Reimport: &Reimported{Test: 1}}, State: stateWith(finding(1, true)),
		Exchanges: []Exchange{{Method: http.MethodPost, Path: "/a", Status: 201}},
	})
	actual := recording(StepRecord{
		Name: "reimport", Result: Result{Error: &Error{Status: 500}}, State: stateWith(finding(1, false), finding(2, true)),
	})

	assert.Equal(t, []string{
		`step 1 "reimport": result.error: recorded nothing, got {"status":500}`,
		`step 1 "reimport": result.reimport: recorded {"engagement":0,"product":0,"test":1}, got nothing`,
		`step 1 "reimport": state.products[0].engagements[0].tests[0].findings: recorded ` +
			`[{"active":true,"false_p":false,"hash_code":"","is_mitigated":false,"out_of_scope":false,"ref":1,` +
			`"risk_accepted":false,"service":"","severity":"","title":"cve-1 libssl 3.0.0","verified":false}], got ` +
			`[{"active":false,"false_p":false,"hash_code":"","is_mitigated":false,"out_of_scope":false,"ref":1,` +
			`"risk_accepted":false,"service":"","severity":"","title":"cve-1 libssl 3.0.0","verified":false},` +
			`{"active":true,"false_p":false,"hash_code":"","is_mitigated":false,"out_of_scope":false,"ref":2,` +
			`"risk_accepted":false,"service":"","severity":"","title":"cve-1 libssl 3.0.0","verified":false}]`,
	}, Compare(recorded, actual))

	assert.Equal(t, []string{
		`step 1 "reimport": state.products[0].engagements[0].tests[0].findings[0].active: recorded true, got false`,
	}, Compare(
		recording(StepRecord{Name: "reimport", State: stateWith(finding(1, true))}),
		recording(StepRecord{Name: "reimport", State: stateWith(finding(1, false))}),
	), "lists of one length are compared item by item")

	assert.Empty(t, Compare(recorded, recording(StepRecord{Name: "reimport", Result: recorded.Steps[0].Result,
		State: recorded.Steps[0].State})), "exchanges are not compared")
}

func TestCompare_ReportsChangedMissingAndExtraSteps(t *testing.T) {
	assert.Equal(t, []string{
		`step 1 "a": the scenario runs "b"`,
		`step 2 "c": not run`,
	}, Compare(recording(StepRecord{Name: "a"}, StepRecord{Name: "c"}), recording(StepRecord{Name: "b"})))

	assert.Equal(t, []string{`step 2 "c": not recorded`},
		Compare(recording(StepRecord{Name: "a"}), recording(StepRecord{Name: "a"}, StepRecord{Name: "c"})))
}

func TestRefs_NumberIDsInTheOrderTheyAppearAndAscendingWithinAState(t *testing.T) {
	r := refs{}

	r.learn(stateWith(finding(50, true), finding(40, true)))
	r.learn(stateWith(finding(50, true), finding(40, true), finding(30, true)))

	got := r.normalize(stateWith(finding(30, true), finding(50, true), finding(40, true)), "")

	refsOf := func(s State) []int {
		findings := s.Products[0].Engagements[0].Tests[0].Findings

		out := make([]int, 0, len(findings))
		for _, f := range findings {
			out = append(out, f.Ref)
		}

		return out
	}

	assert.Equal(t, []int{1, 2, 3}, refsOf(got), "40 and 50 are first seen together, 30 later; findings are ordered by ordinal")
	assert.Equal(t, 0, r.of(kindFinding, 99), "an unknown ID has no ordinal")
}

func TestNormalize_FoldsTitlesAndReplacesTheRunNameInAnyCase(t *testing.T) {
	r := refs{}
	s := State{Products: []ProductState{{Ref: 7, Name: "ddcontract-1a2b/ns", Engagements: []EngagementState{{
		Ref: 3, Tests: []TestState{{Ref: 9, Findings: []FindingState{{Ref: 4, Title: "CVE-1 Libssl 3.0.0"}}}},
	}}}}}
	r.learn(s)

	got := r.normalize(s, "ddcontract-1a2b")

	assert.Equal(t, "ddcontract/ns", got.Products[0].Name)
	assert.Equal(t, "cve-1 libssl 3.0.0", got.Products[0].Engagements[0].Tests[0].Findings[0].Title)
	assert.Equal(t, []string{}, got.Products[0].Tags, "no tags is an empty list")
	assert.Equal(t, "DDCONTRACT/NS", replaceRun("DDCONTRACT-1A2B/NS", "ddcontract-1a2b"))
	assert.Equal(t, "ddcontract/ns", replaceRun("Ddcontract-1a2b/ns", "ddcontract-1a2b"))
}

func TestLive_RecordsTheClientRequestsWithoutCredentials(t *testing.T) {
	const (
		apiToken = "0123456789abcdef"
		run      = "ddcontract-1a2b"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		assert.Equal(t, "Token "+apiToken, r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"test_id":5,"product_name":"`+run+`/ns","url":"http://dojo.example:8080/api/v2/tests/5/",`+
			`"lead":"someone@corp.example"}`)
	}))
	defer srv.Close()

	live := NewLive(srv.URL, apiToken, run)
	r := NewRunner(live, run)

	res, err := r.Reimport(context.Background(), r.request("ns", vulnTitle, app.Service(), VulnerabilityReport(app, vulnA)))
	require.NoError(t, err)
	assert.Equal(t, 5, res.Reimport.Test)

	exchanges := live.TakeExchanges()
	require.Len(t, exchanges, 1)
	assert.Empty(t, live.TakeExchanges(), "taken exchanges are cleared")

	x := exchanges[0]
	assert.Equal(t, http.MethodPost, x.Method)
	assert.Equal(t, "/api/v2/reimport-scan/", x.Path)
	assert.Equal(t, http.StatusCreated, x.Status)
	assert.Contains(t, x.Form, [2]string{"product_name", "ddcontract/ns"})
	assert.Contains(t, x.Form, [2]string{"scan_type", "Trivy Operator Scan"})
	assert.JSONEq(t, string(VulnerabilityReport(app, vulnA)), string(x.File))
	assert.JSONEq(t, `{"test_id":5,"product_name":"ddcontract/ns","url":"http://defectdojo/api/v2/tests/5/",`+
		`"lead":"user@example.com"}`, string(x.Response))

	raw, err := json.Marshal(exchanges)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), apiToken)
	assert.NotContains(t, string(raw), run)
}

func TestLive_RecordsAnAnswerThatIsNotJSONAsShortText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "<html>"+string(make([]byte, 500))+"</html>")
	}))
	defer srv.Close()

	live := NewLive(srv.URL, "t", "ddcontract-1a2b")

	require.Error(t, live.SetBuildID(context.Background(), 1, "m"))

	x := live.TakeExchanges()[0]
	assert.JSONEq(t, `{"build_id":"m"}`, string(x.Body))

	var text string
	require.NoError(t, json.Unmarshal(x.Response, &text))
	assert.Len(t, text, maxTextLen)
}

func TestFixture_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	f := Fixture{DefectDojo: Server{Version: "3.5.200"}, Recording: recording(StepRecord{
		Name: "reimport", Result: Result{Reimport: &Reimported{Test: 1}}, State: stateWith(finding(1, true)),
		Exchanges: []Exchange{{Method: http.MethodPost, Path: "/a", File: json.RawMessage(`{"a":1}`), Status: 201}},
	})}

	require.NoError(t, WriteFixture(dir, f))

	got, err := LoadFixture(dir, "s")
	require.NoError(t, err)
	assert.Equal(t, f.DefectDojo, got.DefectDojo)
	assert.Empty(t, Compare(f.Recording, got.Recording))
	assert.FileExists(t, filepath.Join(dir, "s.json"))
}

func TestScenarios_HaveUniqueNamesAndFixtures(t *testing.T) {
	seen := map[string]bool{}

	for _, s := range Scenarios() {
		assert.False(t, seen[s.Name], "scenario %q twice", s.Name)
		seen[s.Name] = true

		f, err := LoadFixture(DefaultFixtureDir(), s.Name)
		require.NoError(t, err, "record it with make defectdojo-record")
		require.Len(t, f.Steps, len(s.Steps), "the scenario %q changed: record it again", s.Name)

		for i, step := range s.Steps {
			assert.Equal(t, step.Name, f.Steps[i].Name, "the scenario %q changed: record it again", s.Name)
		}
	}
}

func TestBodyFields_NamesTheRejectedFieldsOfAJSONBody(t *testing.T) {
	for body, want := range map[string][]string{
		`{"version": ["This field may not be blank."], "message": "version: ...", "pro": ["..."]}`: {"version"},
		`{"message": "Expecting property name", "pro": ["..."]}`:                                   nil,
		`{"tags": ["Invalid tag: 'a b:1'."], "message": "tags: Invalid tag: 'a b`:                  {"tags"},
		`{"a": 1, "b": {"c": [1, 2]}}`:                                                             {"a", "b"},
		`invalid report: unexpected end of JSON input`:                                             nil,
		`["x"]`: nil,
	} {
		assert.Equal(t, want, bodyFields(body), body)
	}
}

func TestServer_CheckRefusesDeduplicationAndAcceptsAnyVersion(t *testing.T) {
	require.ErrorIs(t, Server{Version: "3.5.200", Deduplication: true}.Check(), ErrDeduplication)
	assert.NoError(t, Server{Version: "3.5.200"}.Check())
	assert.NoError(t, Server{Version: "3.6.0"}.Check())
}
