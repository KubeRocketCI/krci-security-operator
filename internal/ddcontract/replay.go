package ddcontract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// ReplayRequests runs the scenario through the operator client against a server that answers every request of a
// step with the next recorded answer of that step, and returns the differences between the requests the client sends
// and the recorded ones; none when they agree. The state after each step is the recorded one. IDs in paths and queries
// are compared as {id}, timestamps in JSON bodies as {time}. When the scenario stops, the differences of the steps
// that ran are returned with the error.
func ReplayRequests(ctx context.Context, s Scenario, f Fixture) ([]string, error) {
	if len(f.Steps) == 0 {
		return nil, fmt.Errorf("the fixture of %s has no steps", s.Name)
	}

	answers := &recordedAnswers{queue: slices.Clone(f.Steps[0].Exchanges)}

	srv := httptest.NewServer(answers)
	defer srv.Close()

	target := &replayTarget{Live: NewLive(srv.URL, "replay", Canonical), fixture: f, answers: answers}

	rec, err := NewRunner(target, Canonical).Run(ctx, s)

	var diffs []string

	for i := range min(len(f.Steps), len(rec.Steps)) {
		prefix := fmt.Sprintf("step %d %q: ", i+1, f.Steps[i].Name)
		diffs = diffRequests(diffs, prefix, f.Steps[i].Exchanges, rec.Steps[i].Exchanges)
	}

	return diffs, err
}

// replayTarget sends the client calls to the replay server and returns the recorded state; the changes of a
// DefectDojo user are not client calls and do nothing.
type replayTarget struct {
	*Live

	fixture Fixture
	answers *recordedAnswers
	step    int
}

func (t *replayTarget) Triage(context.Context, int, Triage) error { return nil }

func (t *replayTarget) EnableRiskAcceptance(context.Context, int) error { return nil }

func (t *replayTarget) AddEngagement(context.Context, int, string) error { return nil }

// Snapshot returns the recorded state after the step that ran last, whose ordinals stand in for the IDs, and
// queues the recorded answers of the next step.
func (t *replayTarget) Snapshot(context.Context, string) (State, error) {
	if t.step >= len(t.fixture.Steps) {
		return State{}, fmt.Errorf("the fixture has %d steps", len(t.fixture.Steps))
	}

	state := t.fixture.Steps[t.step].State
	t.step++

	var next []Exchange
	if t.step < len(t.fixture.Steps) {
		next = t.fixture.Steps[t.step].Exchanges
	}

	t.answers.load(next)

	return state, nil
}

// recordedAnswers answers each request with the next recorded answer of the current step.
type recordedAnswers struct {
	mu    sync.Mutex
	queue []Exchange
}

// load replaces the answers with those of the next step.
func (a *recordedAnswers) load(exchanges []Exchange) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.queue = slices.Clone(exchanges)
}

func (a *recordedAnswers) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()

	if len(a.queue) == 0 {
		a.mu.Unlock()
		http.Error(w, "no recorded answer", http.StatusNotImplemented)

		return
	}

	next := a.queue[0]
	a.queue = a.queue[1:]
	a.mu.Unlock()

	body := []byte(next.Response)

	var text string
	if json.Unmarshal(next.Response, &text) == nil {
		body = []byte(text)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(next.Status)
	_, _ = w.Write(body)
}

// diffRequests appends a line for every request of a step that differs from the recorded one.
func diffRequests(diffs []string, prefix string, want, got []Exchange) []string {
	for i := range max(len(want), len(got)) {
		switch {
		case i >= len(want):
			diffs = append(diffs, fmt.Sprintf("%srequest %d %s %s: not recorded", prefix, i+1, got[i].Method,
				requestPath(got[i].Path)))
		case i >= len(got):
			diffs = append(diffs, fmt.Sprintf("%srequest %d %s %s: not sent", prefix, i+1, want[i].Method,
				requestPath(want[i].Path)))
		default:
			diffs = diffRequest(diffs, fmt.Sprintf("%srequest %d ", prefix, i+1), want[i], got[i])
		}
	}

	return diffs
}

func diffRequest(diffs []string, prefix string, want, got Exchange) []string {
	wantPath, gotPath := requestPath(want.Path), requestPath(got.Path)
	prefix += want.Method + " " + wantPath + ": "

	if want.Method != got.Method || wantPath != gotPath {
		return append(diffs, fmt.Sprintf("%ssent %s %s", prefix, got.Method, gotPath))
	}

	for i := range max(len(want.Form), len(got.Form)) {
		w, g := formField(want.Form, i), formField(got.Form, i)
		if w != g {
			diffs = append(diffs, fmt.Sprintf("%sform: recorded %s, got %s", prefix, w, g))
		}
	}

	if w, g := comparableJSON(want.File), comparableJSON(got.File); w != g {
		diffs = append(diffs, fmt.Sprintf("%sfile: recorded %s, got %s", prefix, w, g))
	}

	if w, g := comparableJSON(want.Body), comparableJSON(got.Body); w != g {
		diffs = append(diffs, fmt.Sprintf("%sbody: recorded %s, got %s", prefix, w, g))
	}

	return diffs
}

func formField(form [][2]string, i int) string {
	if i >= len(form) {
		return nothing
	}

	return form[i][0] + "=" + form[i][1]
}

var (
	idSegment = regexp.MustCompile(`/\d+/`)
	timestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)
)

// idQueryKeys are the query parameters of the client that hold an ID; the last three are named like the object kinds.
var idQueryKeys = []string{"prod_type", kindProduct, kindEngagement, kindTest}

// requestPath is the path with {id} for numeric segments and the values of idQueryKeys; the query is sorted.
func requestPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	path := idSegment.ReplaceAllString(u.Path, "/{id}/")

	q := u.Query()
	for _, k := range idQueryKeys {
		if q.Has(k) {
			q.Set(k, "{id}")
		}
	}

	if len(q) == 0 {
		return path
	}

	return path + "?" + strings.ReplaceAll(q.Encode(), "%7Bid%7D", "{id}")
}

// comparableJSON is the compact JSON with {time} for timestamps; the text itself when it is not JSON.
func comparableJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return nothing
	}

	var buf bytes.Buffer
	if json.Compact(&buf, raw) != nil {
		return string(raw)
	}

	return timestamp.ReplaceAllString(buf.String(), "{time}")
}
