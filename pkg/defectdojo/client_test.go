package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "secret-token"

func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) *Client {
	t.Helper()

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	opts = append([]Option{WithRetry(2, time.Millisecond)}, opts...)

	return New(opts...).WithCredentials(srv.URL+"/", testToken)
}

func testRequest() ReimportRequest {
	return ReimportRequest{
		ProductType: "KubeRocketCI",
		Product:     "app",
		Engagement:  "runtime-cdp-dev",
		TestTitle:   "VulnerabilityReport deployment/app/app",
		Service:     "ns/Deployment/app/app",
		Version:     "1.0.0",
		BuildID:     "uid-1:100:0123456789ab",
		Tags:        []string{"k8s-cluster:c", "k8s-workload:deployment.app", "app:shop"},
		ScanDate:    time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
		Report:      []byte(`{"kind":"VulnerabilityReport"}`),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestClient_Reimport_SendsMultipartFields(t *testing.T) {
	var (
		fields map[string][]string
		file   string
		auth   string
		path   string
	)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		path = r.URL.Path

		require.NoError(t, r.ParseMultipartForm(1<<20))

		fields = r.MultipartForm.Value

		f, _, err := r.FormFile("file")
		require.NoError(t, err)

		b, err := io.ReadAll(f)
		require.NoError(t, err)

		file = string(b)

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 7, EngagementID: 8, ProductID: 9})
	})

	res, err := c.Reimport(context.Background(), testRequest())

	require.NoError(t, err)
	assert.Equal(t, ReimportResult{TestID: 7, EngagementID: 8, ProductID: 9}, res)
	assert.Equal(t, "Token "+testToken, auth)
	assert.Equal(t, "/api/v2/reimport-scan/", path)
	assert.JSONEq(t, `{"kind":"VulnerabilityReport"}`, file)
	assert.Equal(t, map[string][]string{
		"scan_type":                   {"Trivy Operator Scan"},
		"product_type_name":           {"KubeRocketCI"},
		"product_name":                {"app"},
		"engagement_name":             {"runtime-cdp-dev"},
		"test_title":                  {"VulnerabilityReport deployment/app/app"},
		"service":                     {"ns/Deployment/app/app"},
		"version":                     {"1.0.0"},
		"build_id":                    {"uid-1:100:0123456789ab"},
		"auto_create_context":         {"true"},
		"close_old_findings":          {"true"},
		"deduplication_on_engagement": {"true"},
		"active":                      {"true"},
		"verified":                    {"false"},
		"minimum_severity":            {"Info"},
		"environment":                 {"Development"},
		"push_to_jira":                {"false"},
		"scan_date":                   {"2026-11-10"},
		"tags":                        {"k8s-cluster:c", "k8s-workload:deployment.app", "app:shop"},
	}, fields, "the form has the service, the version, the build_id and one tags field per tag, and no apply_tags_to_findings")
}

func TestClient_Reimport_OmitsAnEmptyBuildID(t *testing.T) {
	var fields map[string][]string

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(1<<20))

		fields = r.MultipartForm.Value

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 7})
	})

	req := testRequest()
	req.BuildID = ""

	_, err := c.Reimport(context.Background(), req)

	require.NoError(t, err)
	assert.NotContains(t, fields, "build_id", "DefectDojo refuses a blank build_id; an omitted one is stored as empty")
}

func TestClient_Reimport_RejectsAnEmptyService(t *testing.T) {
	var calls atomic.Int32

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 7})
	})

	req := testRequest()
	req.Service = ""

	_, err := c.Reimport(context.Background(), req)

	require.ErrorIs(t, err, ErrServiceRequired)
	assert.Zero(t, calls.Load(), "nothing is sent")
}

func TestClient_Reimport_Retries(t *testing.T) {
	tests := []struct {
		name         string
		statuses     []int
		wantAttempts int32
		wantStatus   int
		wantErr      bool
	}{
		{name: "429 then success", statuses: []int{429, 201}, wantAttempts: 2},
		{name: "429 until retries are exhausted", statuses: []int{429, 429, 429, 201}, wantAttempts: 3, wantStatus: 429, wantErr: true},
		{name: "500 is not retried", statuses: []int{500, 201}, wantAttempts: 1, wantStatus: 500, wantErr: true},
		{name: "502 is not retried", statuses: []int{502, 201}, wantAttempts: 1, wantStatus: 502, wantErr: true},
		{name: "503 is not retried", statuses: []int{503, 201}, wantAttempts: 1, wantStatus: 503, wantErr: true},
		{name: "429 then 500 stops at the 500", statuses: []int{429, 500, 201}, wantAttempts: 2, wantStatus: 500, wantErr: true},
		{name: "400 is not retried", statuses: []int{400, 201}, wantAttempts: 1, wantStatus: 400, wantErr: true},
		{name: "401 is not retried", statuses: []int{401, 201}, wantAttempts: 1, wantStatus: 401, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32

			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				status := tt.statuses[attempts.Add(1)-1]
				writeJSON(w, status, ReimportResult{TestID: 1})
			})

			_, err := c.Reimport(context.Background(), testRequest())

			assert.Equal(t, tt.wantAttempts, attempts.Load())

			if !tt.wantErr {
				require.NoError(t, err)

				return
			}

			var apiErr *APIError

			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, tt.wantStatus, apiErr.StatusCode)
		})
	}
}

func TestClient_Reimport_DoesNotRetryTransportError(t *testing.T) {
	var attempts atomic.Int32

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			require.NoError(t, conn.Close())

			return
		}

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 1})
	})

	_, err := c.Reimport(context.Background(), testRequest())

	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load(), "DefectDojo may still process the request")
}

func TestClient_Reimport_DoesNotRetryTimeout(t *testing.T) {
	var attempts atomic.Int32

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)

		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
		}

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 1})
	}, WithHTTPClient(&http.Client{Timeout: 30 * time.Millisecond}))

	_, err := c.Reimport(context.Background(), testRequest())

	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load(), "a timed-out re-import is not sent again")
}

func TestClient_Reads_RetryTransportErrorAndServerError(t *testing.T) {
	var attempts atomic.Int32

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == productsPath {
			writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": []Product{{ID: 3, Name: "a/ns"}}})

			return
		}

		switch attempts.Add(1) {
		case 1:
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			require.NoError(t, conn.Close())
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": []map[string]any{{"id": 1, "name": "KubeRocketCI"}}})
		}
	})

	products, err := c.ListProducts(context.Background(), "KubeRocketCI", "a/")

	require.NoError(t, err)
	assert.Equal(t, []Product{{ID: 3, Name: "a/ns"}}, products)
	assert.Equal(t, int32(3), attempts.Load(), "the product type lookup was retried")
}

func TestClient_RequestTimeouts(t *testing.T) {
	assert.Equal(t, 10*time.Minute, reimportTimeout)
	assert.Equal(t, 2*time.Minute, defaultRequestTimeout)
}

func TestClient_Reimport_StopsWaitingWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// 429 is the one answer a reimport retries, so the client waits for the backoff.
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		cancel()
		w.WriteHeader(http.StatusTooManyRequests)
	}, WithRetry(5, time.Hour))

	_, err := c.Reimport(ctx, testRequest())

	require.ErrorIs(t, err, context.Canceled)
}

func TestIsRejectedReport(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "bad request", err: &APIError{StatusCode: 400}, want: true},
		{name: "unprocessable", err: &APIError{StatusCode: 422}, want: true},
		{name: "unauthorized", err: &APIError{StatusCode: 401}},
		{name: "forbidden", err: &APIError{StatusCode: 403}},
		{name: "too many requests", err: &APIError{StatusCode: 429}},
		{name: "server error", err: &APIError{StatusCode: 500}},
		{name: "transport error", err: fmt.Errorf("connection refused")},
		{name: "wrapped", err: fmt.Errorf("wrap: %w", &APIError{StatusCode: 400}), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsRejectedReport(tt.err))
		})
	}
}

// inFlightTracker counts concurrent requests per test title.
type inFlightTracker struct {
	mu      sync.Mutex
	current map[string]int
	maxSeen map[string]int
	total   int
	maxAll  int
	hold    time.Duration
}

func newInFlightTracker(hold time.Duration) *inFlightTracker {
	return &inFlightTracker{current: map[string]int{}, maxSeen: map[string]int{}, hold: hold}
}

func (f *inFlightTracker) handler(w http.ResponseWriter, r *http.Request) {
	title := r.FormValue("test_title")

	f.mu.Lock()
	f.current[title]++
	f.total++
	f.maxSeen[title] = max(f.maxSeen[title], f.current[title])
	f.maxAll = max(f.maxAll, f.total)
	f.mu.Unlock()

	time.Sleep(f.hold)

	f.mu.Lock()
	f.current[title]--
	f.total--
	f.mu.Unlock()

	writeJSON(w, http.StatusCreated, ReimportResult{TestID: 1})
}

func runConcurrently(t *testing.T, c *Client, titles []string) {
	t.Helper()

	var wg sync.WaitGroup

	for _, title := range titles {
		wg.Add(1)

		go func() {
			defer wg.Done()

			r := testRequest()
			r.TestTitle = title

			_, err := c.Reimport(context.Background(), r)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}

func TestClient_Reimport_OneImportAtATimePerTest(t *testing.T) {
	tracker := newInFlightTracker(20 * time.Millisecond)
	c := newTestClient(t, tracker.handler)

	_, err := c.Reimport(context.Background(), testRequest())
	require.NoError(t, err)

	runConcurrently(t, c, []string{"same", "same", "same", "same"})

	assert.Equal(t, 1, tracker.maxSeen["same"])
}

func TestClient_Reimport_DifferentTestsOfKnownContextRunInParallel(t *testing.T) {
	tracker := newInFlightTracker(50 * time.Millisecond)
	c := newTestClient(t, tracker.handler)

	_, err := c.Reimport(context.Background(), testRequest())
	require.NoError(t, err)

	runConcurrently(t, c, []string{"a", "b", "c"})

	assert.Greater(t, tracker.maxAll, 1)
}

func TestClient_Reimport_FirstImportsOfAnUnknownContextAreSerialised(t *testing.T) {
	tracker := newInFlightTracker(30 * time.Millisecond)
	c := newTestClient(t, tracker.handler)

	runConcurrently(t, c, []string{"a", "b", "c"})

	assert.Equal(t, 1, tracker.maxAll)
}

func TestClient_Reimport_FailedFirstImportKeepsContextUnknown(t *testing.T) {
	var fail atomic.Bool

	fail.Store(true)

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 1})
	})

	_, err := c.Reimport(context.Background(), testRequest())
	require.Error(t, err)
	assert.False(t, c.isKnown(c.contextKey("app", "runtime-cdp-dev")))

	fail.Store(false)

	_, err = c.Reimport(context.Background(), testRequest())
	require.NoError(t, err)
	assert.True(t, c.isKnown(c.contextKey("app", "runtime-cdp-dev")))
}

func TestClient_Reimport_KnownContextIsKeyedByBaseURL(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 1})
	})

	_, err := c.Reimport(context.Background(), testRequest())
	require.NoError(t, err)

	moved := c.WithCredentials("https://other.example.com", "t")

	assert.True(t, c.isKnown(c.contextKey("app", "runtime-cdp-dev")))
	assert.False(t, moved.isKnown(moved.contextKey("app", "runtime-cdp-dev")), "another instance starts unknown")
	assert.NotEqual(t, c.contextKey("app", "e"), moved.contextKey("app", "e"))
}

// findingsServer serves the active findings of test 42 page by page and records the closed ones. A reimport of
// test 42 with an empty report closes the active findings of the request service, as DefectDojo does, and answers
// with the statistics of the test.
type findingsServer struct {
	t      *testing.T
	mu     sync.Mutex
	active []map[string]any
	closed []int
	bodies []map[string]any
	posts  atomic.Int32
	failOn int32
	// patches holds the test update bodies, in order; order records every request as "<method> <path>".
	patches []map[string]any
	order   []string
	// limits holds the limit of each read of the findings, in order.
	limits []string
	// reimports holds the form fields and the file of each reimport request, in order.
	reimports []reimportCall
	// reimportStatus, when not zero, is the answer to a reimport; the findings stay active.
	reimportStatus int
	reimportBody   string
	// noStatistics leaves the statistics out of the answer to a reimport.
	noStatistics bool
	// triaged holds findings that the list of active findings does not return: false positive, out of scope, risk
	// accepted. A reimport mitigates those of its service, as DefectDojo 3.5.200 does, and removes the risk acceptance.
	triaged []triagedFinding
	// reimportKeeps answers a reimport with 201 and leaves every finding active.
	reimportKeeps bool
	// dropReimport closes the connection of a reimport without an answer. onReimport, when set, runs first.
	dropReimport bool
	onReimport   func()
}

type triagedFinding struct {
	id        int
	service   string
	state     string
	mitigated bool
}

const (
	falsePositive = "false_p"
	riskAccepted  = "risk_accepted"
	outOfScope    = "out_of_scope"
)

type reimportCall struct {
	fields map[string][]string
	file   string
}

func (f *findingsServer) handleReimport(w http.ResponseWriter, r *http.Request) {
	require.NoError(f.t, r.ParseMultipartForm(1<<20))

	file, _, err := r.FormFile("file")
	require.NoError(f.t, err)

	content, err := io.ReadAll(file)
	require.NoError(f.t, err)

	call := reimportCall{fields: r.MultipartForm.Value, file: string(content)}
	f.reimports = append(f.reimports, call)

	if f.onReimport != nil {
		f.onReimport()
	}

	if f.dropReimport {
		conn, _, err := w.(http.Hijacker).Hijack()
		require.NoError(f.t, err)
		require.NoError(f.t, conn.Close())

		return
	}

	if f.reimportStatus != 0 {
		w.WriteHeader(f.reimportStatus)
		_, _ = w.Write([]byte(f.reimportBody))

		return
	}

	service := ""
	if s := call.fields["service"]; len(s) > 0 {
		service = s[0]
	}

	if !f.reimportKeeps {
		for i := range f.triaged {
			if f.triaged[i].service == service {
				f.triaged[i].mitigated = true

				if f.triaged[i].state == riskAccepted {
					f.triaged[i].state = ""
				}
			}
		}

		f.active = slices.DeleteFunc(f.active, func(a map[string]any) bool {
			have, _ := a["service"].(string)

			return have == service
		})
	}

	answer := map[string]any{"test_id": 42}
	if !f.noStatistics {
		answer["statistics"] = map[string]any{
			"after": map[string]any{"total": map[string]any{"active": len(f.active)}},
		}
	}

	writeJSON(w, http.StatusCreated, answer)
}

func (f *findingsServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	assert.Equal(f.t, "Token "+testToken, r.Header.Get("Authorization"))

	f.order = append(f.order, r.Method+" "+r.URL.Path)

	if r.URL.Path == reimportPath {
		f.handleReimport(w, r)

		return
	}

	if r.Method == http.MethodPatch {
		assert.Equal(f.t, "/api/v2/tests/42/", r.URL.Path)

		body := map[string]any{}
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))

		f.patches = append(f.patches, body)

		writeJSON(w, http.StatusOK, map[string]any{})

		return
	}

	if r.Method == http.MethodGet {
		assert.Equal(f.t, "/api/v2/findings/", r.URL.Path)
		assert.Equal(f.t, "42", r.URL.Query().Get("test"))
		assert.Equal(f.t, "true", r.URL.Query().Get("active"))
		assert.Equal(f.t, "false", r.URL.Query().Get("is_mitigated"))

		f.limits = append(f.limits, r.URL.Query().Get("limit"))

		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		end := min(offset+limit, len(f.active))

		var next *string

		if end < len(f.active) {
			n := "http://next"
			next = &n
		}

		writeJSON(w, http.StatusOK, map[string]any{"next": next, "results": f.active[offset:end]})

		return
	}

	if f.posts.Add(1) == f.failOn {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	var id int

	_, err := fmt.Sscanf(r.URL.Path, "/api/v2/findings/%d/close/", &id)
	require.NoError(f.t, err)

	body := map[string]any{}
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))

	f.bodies = append(f.bodies, body)
	f.closed = append(f.closed, id)
	f.active = slices.DeleteFunc(f.active, func(a map[string]any) bool { return a["id"] == float64(id) || a["id"] == id })

	writeJSON(w, http.StatusOK, map[string]any{})
}

func newFindingsServer(t *testing.T, services ...string) *findingsServer {
	t.Helper()

	f := &findingsServer{t: t}

	for i, s := range services {
		// DefectDojo answers null for a finding without a service.
		var service any
		if s != "" {
			service = s
		}

		f.active = append(f.active, map[string]any{"id": i + 1, "service": service})
	}

	return f
}

const closeService = "ns/Deployment/app/app"

// closableTest holds an upload marker in its build_id.
var closableTest = Test{
	ID: 42, Title: "VulnerabilityReport deployment/app/app", Version: "1.2.3", BuildID: "uid-1:100:0123456789ab",
	Product: "a/ns", Engagement: "trivy-operator",
}

const (
	readFindings = "GET /api/v2/findings/"
	reimportScan = "POST /api/v2/reimport-scan/"
	patchTest    = "PATCH /api/v2/tests/42/"
	closeOne     = "POST /api/v2/findings/%d/close/"
)

// closeTest closes the test and returns how it was closed.
func closeTest(t *testing.T, c *Client, test Test) CloseResult {
	t.Helper()

	res, err := c.CloseTest(context.Background(), test)
	require.NoError(t, err)

	return res
}

func closeErr(ctx context.Context, c *Client, test Test) error {
	_, err := c.CloseTest(ctx, test)

	return err
}

func services(n int, service string) []string { return slices.Repeat([]string{service}, n) }

func TestClient_CloseTest_ClosesATestOfThousandsOfFindingsWithOneRequest(t *testing.T) {
	f := newFindingsServer(t, services(2000, closeService)...)
	c := newTestClient(t, f.handle)

	res := closeTest(t, c, closableTest)

	assert.Equal(t, CloseResult{Reimports: 1}, res)
	assert.True(t, res.FoundActive())
	assert.Empty(t, f.active)
	assert.Empty(t, f.closed, "no finding is closed one by one")
	assert.Equal(t, []string{patchTest, readFindings, reimportScan}, f.order,
		"the build_id is cleared, one finding is read for its service, then one reimport closes the test")
	assert.Equal(t, []string{"1"}, f.limits, "only one finding is read, not the 2000")
}

func TestClient_CloseTest_TheReimportMitigatesTheTriagedFindingsOfItsServiceOnly(t *testing.T) {
	f := newFindingsServer(t, closeService)
	f.triaged = []triagedFinding{
		{id: 10, service: closeService, state: falsePositive},
		{id: 11, service: closeService, state: riskAccepted},
		{id: 12, service: closeService, state: outOfScope},
		{id: 13, service: "ns/Deployment/other/app", state: falsePositive},
	}
	c := newTestClient(t, f.handle)

	closeTest(t, c, closableTest)

	assert.Equal(t, []triagedFinding{
		{id: 10, service: closeService, state: falsePositive, mitigated: true},
		{id: 11, service: closeService, state: "", mitigated: true},
		{id: 12, service: closeService, state: outOfScope, mitigated: true},
		{id: 13, service: "ns/Deployment/other/app", state: falsePositive},
	}, f.triaged, "flags stay, the risk acceptance goes, another service is untouched")
}

func TestClient_CloseTest_LeavesTheTriagedFindingsOfATestWithoutActiveFindings(t *testing.T) {
	f := newFindingsServer(t)
	f.triaged = []triagedFinding{{id: 10, service: closeService, state: riskAccepted}}
	c := newTestClient(t, f.handle)

	closeTest(t, c, closableTest)

	assert.Equal(t, []triagedFinding{{id: 10, service: closeService, state: riskAccepted}}, f.triaged)
	assert.Empty(t, f.reimports)
}

func TestClient_CloseTest_ClearsTheBuildIDBeforeTheReimport(t *testing.T) {
	f := newFindingsServer(t, closeService)
	c := newTestClient(t, f.handle)

	closeTest(t, c, closableTest)

	assert.Equal(t, []map[string]any{{"build_id": ""}}, f.patches)
	assert.Equal(t, patchTest, f.order[0], "a reimport that is cut short before it saves the test leaves no marker")
}

func TestClient_CloseTest_LeavesAnEmptyBuildIDAlone(t *testing.T) {
	f := newFindingsServer(t, closeService)
	c := newTestClient(t, f.handle)

	test := closableTest
	test.BuildID = ""

	closeTest(t, c, test)

	assert.Equal(t, []string{readFindings, reimportScan}, f.order)
	assert.Empty(t, f.patches)
}

func TestClient_CloseTest_ReimportsAnEmptyReportOfTheTestByID(t *testing.T) {
	f := newFindingsServer(t, closeService)
	c := newTestClient(t, f.handle)

	closeTest(t, c, closableTest)

	require.Len(t, f.reimports, 1)
	assert.Equal(t, map[string][]string{
		"test":               {"42"},
		"scan_type":          {"Trivy Operator Scan"},
		"service":            {closeService},
		"version":            {"1.2.3"},
		"close_old_findings": {"true"},
	}, f.reimports[0].fields, "the test is named by its ID; tags, scan_date and build_id are left out")
	assert.JSONEq(t, `{"metadata": {"labels": {}}, "report": {"vulnerabilities": []}}`, f.reimports[0].file)
}

func TestClient_CloseTest_TheEmptyReportIsTheSameForEveryTitle(t *testing.T) {
	for _, title := range []string{
		"VulnerabilityReport deployment/app/app", "ExposedSecretReport deployment/app/app", "scan of app",
	} {
		t.Run(title, func(t *testing.T) {
			f := newFindingsServer(t, closeService)
			c := newTestClient(t, f.handle)

			test := closableTest
			test.Title = title

			closeTest(t, c, test)

			require.Len(t, f.reimports, 1)
			assert.JSONEq(t, `{"metadata": {"labels": {}}, "report": {"vulnerabilities": []}}`, f.reimports[0].file)
		})
	}
}

func TestClient_CloseTest_OmitsWhatTheTestAndItsFindingLack(t *testing.T) {
	f := newFindingsServer(t, "")
	c := newTestClient(t, f.handle)

	test := closableTest
	test.Version = ""

	closeTest(t, c, test)

	require.Len(t, f.reimports, 1)
	assert.Equal(t, map[string][]string{
		"test":               {"42"},
		"scan_type":          {"Trivy Operator Scan"},
		"close_old_findings": {"true"},
	}, f.reimports[0].fields, "a finding without a service closes through a reimport without one; no blank version")
	assert.Empty(t, f.active)
}

func TestClient_CloseTest_ReimportsOncePerServiceOfTheTest(t *testing.T) {
	f := newFindingsServer(t, "", closeService, closeService, "ns/Deployment/other/app")
	c := newTestClient(t, f.handle)

	res := closeTest(t, c, closableTest)

	assert.Equal(t, CloseResult{Reimports: 3}, res)
	assert.Equal(t, []string{
		patchTest, readFindings, reimportScan, readFindings, reimportScan, readFindings, reimportScan,
	}, f.order, "the first finding listed is of no service: each service that stays active gets its own reimport")
	assert.Empty(t, f.active)
	assert.Empty(t, f.closed)
	assert.Len(t, f.patches, 1, "the build_id is cleared once")

	require.Len(t, f.reimports, 3)
	assert.NotContains(t, f.reimports[0].fields, "service")
	assert.Equal(t, []string{closeService}, f.reimports[1].fields["service"])
	assert.Equal(t, []string{"ns/Deployment/other/app"}, f.reimports[2].fields["service"])
}

func TestClient_CloseTest_ClosesOneByOneWhatStaysActiveAfterTheBoundOfReimports(t *testing.T) {
	names := make([]string, 0, maxCloseReimports+2)

	for i := range maxCloseReimports + 2 {
		names = append(names, fmt.Sprintf("ns/Deployment/app%d/app", i))
	}

	f := newFindingsServer(t, names...)
	c := newTestClient(t, f.handle)

	res := closeTest(t, c, closableTest)

	assert.Equal(t, CloseResult{Reimports: maxCloseReimports, OneByOne: 2}, res)
	assert.Len(t, f.reimports, maxCloseReimports)
	assert.Equal(t, []int{maxCloseReimports + 1, maxCloseReimports + 2}, f.closed,
		"the findings of the services beyond the bound are closed through the findings")
	assert.Empty(t, f.active)
}

func TestClient_CloseTest_ClosesOneByOneWhenTheReimportOfAServiceClosesNothing(t *testing.T) {
	f := newFindingsServer(t, closeService, "other")
	f.reimportKeeps = true
	c := newTestClient(t, f.handle)

	res := closeTest(t, c, closableTest)

	assert.Equal(t, CloseResult{Reimports: 1, OneByOne: 2}, res)
	assert.Equal(t, []string{
		patchTest, readFindings, reimportScan, readFindings, readFindings, fmt.Sprintf(closeOne, 1), fmt.Sprintf(closeOne, 2),
	}, f.order, "the same service is first again: it is not reimported twice")
	assert.Len(t, f.reimports, 1)
	assert.Empty(t, f.active)

	require.Len(t, f.bodies, 2)

	for _, b := range f.bodies {
		assert.Equal(t, true, b["is_mitigated"])

		mitigated, ok := b["mitigated"].(string)
		require.True(t, ok)

		_, err := time.Parse(time.RFC3339, mitigated)
		require.NoError(t, err)
		assert.True(t, strings.HasSuffix(mitigated, "Z"))
	}
}

func TestClient_CloseTest_ReadsTheActiveFindingsAgainWhenTheAnswerHasNoStatistics(t *testing.T) {
	f := newFindingsServer(t, closeService)
	f.noStatistics = true
	c := newTestClient(t, f.handle)

	closeTest(t, c, closableTest)

	assert.Equal(t, []string{patchTest, readFindings, reimportScan, readFindings}, f.order,
		"without statistics the active findings are read again, and none is left")
}

func TestClient_CloseTest_ClosesOneByOneWhenTheTestCannotBeReimported(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFindingsServer(t, closeService, "other")
			f.reimportStatus = status
			f.reimportBody = `{"test":["Invalid pk \"42\" - object does not exist."]}`
			c := newTestClient(t, f.handle)

			res := closeTest(t, c, closableTest)

			var apiErr *APIError

			require.ErrorAs(t, res.Fallback, &apiErr, "the caller learns why the reimport was not used")
			assert.Equal(t, status, apiErr.StatusCode)
			assert.Contains(t, apiErr.Body, "Invalid pk", "the body of the refusal is kept")
			assert.Equal(t, 2, res.OneByOne)
			assert.Zero(t, res.Reimports)
			assert.True(t, res.FoundActive())
			assert.Equal(t, []string{
				patchTest, readFindings, reimportScan, readFindings, fmt.Sprintf(closeOne, 1), fmt.Sprintf(closeOne, 2),
			}, f.order, "the findings are closed through the findings after the rejected reimport")
			assert.Equal(t, []map[string]any{{"build_id": ""}}, f.patches)
			assert.Equal(t, []int{1, 2}, f.closed)
		})
	}
}

func TestClient_CloseTest_ClosesOneByOneWhenTheReimportFailsOnTheServer(t *testing.T) {
	for _, status := range []int{
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
	} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFindingsServer(t, closeService, "other")
			f.reimportStatus = status
			c := newTestClient(t, f.handle)

			res := closeTest(t, c, closableTest)

			var apiErr *APIError

			require.ErrorAs(t, res.Fallback, &apiErr)
			assert.Equal(t, status, apiErr.StatusCode)
			assert.Equal(t, []string{
				patchTest, readFindings, reimportScan, readFindings, fmt.Sprintf(closeOne, 1), fmt.Sprintf(closeOne, 2),
			}, f.order, "a close that fails the same way on every pass would never end: the findings are closed one by one")
			assert.Equal(t, []int{1, 2}, f.closed)
			assert.Len(t, f.reimports, 1, "the reimport is not repeated")
		})
	}
}

func TestClient_CloseTest_ClosesOneByOneWhenTheReimportAnswerIsLost(t *testing.T) {
	f := newFindingsServer(t, closeService, "other")
	f.dropReimport = true
	c := newTestClient(t, f.handle)

	res := closeTest(t, c, closableTest)

	require.Error(t, res.Fallback)
	assert.Equal(t, 2, res.OneByOne)
	assert.Equal(t, []int{1, 2}, f.closed, "a transport error leaves the result unknown, as a 5xx does")
}

func TestClient_CloseTest_ReturnsTheFailureOfTheReimportThatDoesNotShowTheStateOfTheTest(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusConflict,
		http.StatusTooManyRequests,
	} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFindingsServer(t, closeService)
			f.reimportStatus = status
			c := newTestClient(t, f.handle)

			var apiErr *APIError

			require.ErrorAs(t, closeErr(context.Background(), c, closableTest), &apiErr)
			assert.Equal(t, status, apiErr.StatusCode)
			assert.Equal(t, []string{patchTest, readFindings, reimportScan}, f.order[:3],
				"authentication, throttling, timeout and an import in progress are not a refusal of this request; "+
					"the build_id stays cleared")
			assert.Empty(t, f.closed)
		})
	}
}

func TestClient_CloseTest_StopsWhenTheContextIsDone(t *testing.T) {
	f := newFindingsServer(t, closeService)
	ctx, cancel := context.WithCancel(context.Background())
	f.onReimport = cancel
	f.dropReimport = true
	c := newTestClient(t, f.handle)

	require.Error(t, closeErr(ctx, c, closableTest))
	assert.Empty(t, f.closed, "a cancelled close does not start closing one by one")
}

func TestClient_CloseTest_BuildIDUpdateFailureClosesNothing(t *testing.T) {
	f := newFindingsServer(t, closeService)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		f.handle(w, r)
	})

	var apiErr *APIError

	require.ErrorAs(t, closeErr(context.Background(), c, closableTest), &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	assert.Empty(t, f.order, "nothing is read, re-imported or closed after the refused update")
	assert.Len(t, f.active, 1)
}

func TestClient_CloseTest_NoActiveFindings(t *testing.T) {
	f := newFindingsServer(t)
	c := newTestClient(t, f.handle)

	res := closeTest(t, c, closableTest)

	assert.False(t, res.FoundActive())
	assert.Equal(t, []string{patchTest, readFindings}, f.order,
		"a test without active findings is not reimported; its build_id is cleared")
	assert.Equal(t, []map[string]any{{"build_id": ""}}, f.patches)
}

func TestClient_SetBuildID_PatchesTheTest(t *testing.T) {
	f := newFindingsServer(t)
	c := newTestClient(t, f.handle)

	require.NoError(t, c.SetBuildID(context.Background(), 42, "uid-1:100:0123456789ab"))

	assert.Equal(t, []map[string]any{{"build_id": "uid-1:100:0123456789ab"}}, f.patches)
	assert.Equal(t, []string{"PATCH /api/v2/tests/42/"}, f.order)
}

func TestClient_SetBuildID_RetriesAndReturnsTheFailure(t *testing.T) {
	var patches atomic.Int32

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		patches.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	var apiErr *APIError

	require.ErrorAs(t, c.SetBuildID(context.Background(), 42, "m"), &apiErr)
	assert.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode)
	assert.Greater(t, patches.Load(), int32(1), "the update is idempotent and retried like a read")
}

func TestClient_CloseTest_RetriesTheCloseOfAFinding(t *testing.T) {
	f := newFindingsServer(t, closeService)
	f.reimportStatus = http.StatusBadRequest
	f.failOn = 1
	c := newTestClient(t, f.handle)

	closeTest(t, c, closableTest)

	assert.Equal(t, []int{1}, f.closed)
	assert.Equal(t, int32(2), f.posts.Load(), "the 503 was retried")
}

func TestClient_CloseTest_ServerError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	var apiErr *APIError

	require.ErrorAs(t, closeErr(context.Background(), c, closableTest), &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
}

func TestClient_Close_RequiresTheNamesOfTheTest(t *testing.T) {
	tests := map[string]Test{
		"no product":    {ID: 42, Title: "t", Engagement: "e"},
		"no engagement": {ID: 42, Title: "t", Product: "p"},
		"no title":      {ID: 42, Product: "p", Engagement: "e"},
		"only the ID":   {ID: 42},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32

			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": []map[string]any{{"id": 1}}})
			})

			require.ErrorIs(t, closeErr(context.Background(), c, test), ErrTestNotNamed)

			assert.Zero(t, requests.Load(), "no finding is read or closed")
		})
	}
}

// listingServer serves product types, products, engagements and tests with the filters of the DefectDojo list
// endpoints, two results per page, and records each query.
type listingServer struct {
	t        *testing.T
	mu       sync.Mutex
	queries  map[string][]url.Values
	results  map[string][]any
	pageSize int
}

func newListingServer(t *testing.T, results map[string][]any) *listingServer {
	t.Helper()

	return &listingServer{t: t, queries: map[string][]url.Values{}, results: results, pageSize: 2}
}

func (l *listingServer) handle(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()

	assert.Equal(l.t, http.MethodGet, r.Method)
	assert.Equal(l.t, "Token "+testToken, r.Header.Get("Authorization"))

	l.queries[r.URL.Path] = append(l.queries[r.URL.Path], r.URL.Query())

	all := l.results[r.URL.Path]

	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	require.NoError(l.t, err)

	end := min(offset+l.pageSize, len(all))

	var next *string

	if end < len(all) {
		n := "http://next"
		next = &n
	}

	writeJSON(w, http.StatusOK, map[string]any{"next": next, "results": all[min(offset, end):end]})
}

func TestClient_ListProducts_FiltersByProductTypeAndName(t *testing.T) {
	l := newListingServer(t, map[string][]any{
		productTypesPath: {map[string]any{"id": 4, "name": "KubeRocketCI-old"}, map[string]any{"id": 5, "name": "KubeRocketCI"}},
		productsPath: {
			map[string]any{"id": 1, "name": "a/one", "tags": []string{"k8s-cluster:a"}},
			map[string]any{"id": 2, "name": "x-a/two", "tags": []string{}},
			map[string]any{"id": 3, "name": "a/three", "tags": nil},
		},
	})
	c := newTestClient(t, l.handle)

	products, err := c.ListProducts(context.Background(), "KubeRocketCI", "a/")

	require.NoError(t, err)
	assert.Equal(t, []Product{
		{ID: 1, Name: "a/one", Tags: []string{"k8s-cluster:a"}},
		{ID: 2, Name: "x-a/two", Tags: []string{}},
		{ID: 3, Name: "a/three"},
	}, products, "the name filter is a contains match: the caller checks the prefix; every page is read")

	require.Len(t, l.queries[productTypesPath], 1)
	assert.Equal(t, "KubeRocketCI", l.queries[productTypesPath][0].Get("name"))

	require.Len(t, l.queries[productsPath], 2, "two pages")

	for _, q := range l.queries[productsPath] {
		assert.Equal(t, "5", q.Get("prod_type"), "the ID of the exact product type name")
		assert.Equal(t, "a/", q.Get("name"))
	}
}

func TestClient_ListProductsByName_AsksForTheExactName(t *testing.T) {
	l := newListingServer(t, map[string][]any{
		productTypesPath: {map[string]any{"id": 5, "name": "KubeRocketCI"}},
		productsPath:     {map[string]any{"id": 1, "name": "a/kube", "tags": []string{"k8s-cluster:a"}}},
	})
	c := newTestClient(t, l.handle)

	products, err := c.ListProductsByName(context.Background(), "KubeRocketCI", "a/kube")

	require.NoError(t, err)
	assert.Equal(t, []Product{{ID: 1, Name: "a/kube", Tags: []string{"k8s-cluster:a"}}}, products)

	require.Len(t, l.queries[productsPath], 1)
	assert.Equal(t, "a/kube", l.queries[productsPath][0].Get("name_exact"))
	assert.Empty(t, l.queries[productsPath][0].Get("name"), "no contains filter, so no other product is read")
	assert.Equal(t, "5", l.queries[productsPath][0].Get("prod_type"))
}

func TestClient_ListProductsByName_UnknownProductType(t *testing.T) {
	l := newListingServer(t, map[string][]any{productTypesPath: {}})
	c := newTestClient(t, l.handle)

	_, err := c.ListProductsByName(context.Background(), "KubeRocketCI", "a/kube")

	require.ErrorIs(t, err, ErrProductTypeNotFound)
}

func TestClient_ListProducts_UnknownProductType(t *testing.T) {
	l := newListingServer(t, map[string][]any{productTypesPath: {map[string]any{"id": 4, "name": "Other"}}})
	c := newTestClient(t, l.handle)

	products, err := c.ListProducts(context.Background(), "KubeRocketCI", "a/")

	require.ErrorIs(t, err, ErrProductTypeNotFound)
	assert.Empty(t, products)
	assert.Empty(t, l.queries[productsPath], "no product can be listed under a missing product type")
}

func TestClient_ListProducts_ForgetsTheProductTypeIDOfAnEmptyList(t *testing.T) {
	var (
		mu      sync.Mutex
		typeID  = 5
		lookups int
	)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		results := []map[string]any{}

		switch r.URL.Path {
		case productTypesPath:
			lookups++

			results = append(results, map[string]any{"id": typeID, "name": "KubeRocketCI"})
		case productsPath:
			if r.URL.Query().Get("prod_type") == strconv.Itoa(typeID) {
				results = append(results, map[string]any{"id": 1, "name": "a/ns"})
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": results})
	})

	list := func() []Product {
		products, err := c.ListProducts(context.Background(), "KubeRocketCI", "a/ns")
		require.NoError(t, err)

		return products
	}

	require.Len(t, list(), 1)
	require.Len(t, list(), 1)
	assert.Equal(t, 1, lookups, "the ID is kept while the lists are not empty")

	// The product type was deleted and created again: the kept ID matches nothing.
	mu.Lock()
	typeID = 6
	mu.Unlock()

	assert.Empty(t, list())
	assert.Len(t, list(), 1, "the next list resolves the product type again")
	assert.Equal(t, 2, lookups)
}

func TestClient_ListProducts_ServerError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})

	_, err := c.ListProducts(context.Background(), "KubeRocketCI", "a/")

	var apiErr *APIError

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadGateway, apiErr.StatusCode)
}

func TestClient_ListTests_ThroughEngagementOfProduct(t *testing.T) {
	l := newListingServer(t, map[string][]any{
		engagementsPath: {
			map[string]any{"id": 20, "name": "trivy-operator-extra"},
			map[string]any{"id": 21, "name": "trivy-operator"},
		},
		testsPath: {
			map[string]any{"id": 1, "title": "a", "scan_type": ScanTypeTrivyOperator, "tags": []string{"k8s-workload:x"}, "version": "1.2.3"},
			map[string]any{"id": 2, "title": "b", "scan_type": ScanTypeTrivyOperator, "tags": []string{}},
			map[string]any{"id": 3, "title": "c", "scan_type": "Trivy Scan"},
		},
	})
	c := newTestClient(t, l.handle)

	tests, err := c.ListTests(context.Background(), Product{ID: 9, Name: "a/ns"}, "trivy-operator")

	require.NoError(t, err)
	assert.Equal(t, []Test{
		{
			ID: 1, Title: "a", ScanType: ScanTypeTrivyOperator, Tags: []string{"k8s-workload:x"}, Version: "1.2.3",
			Product: "a/ns", Engagement: "trivy-operator", LastEngagement: true,
		},
		{
			ID: 2, Title: "b", ScanType: ScanTypeTrivyOperator, Tags: []string{},
			Product: "a/ns", Engagement: "trivy-operator", LastEngagement: true,
		},
		{ID: 3, Title: "c", ScanType: "Trivy Scan", Product: "a/ns", Engagement: "trivy-operator", LastEngagement: true},
	}, tests, "scan type, tags, version and build_id are the ones of the response, also when the server ignores the scan type filter; a null build_id is empty")

	require.Len(t, l.queries[engagementsPath], 1)
	assert.Equal(t, "9", l.queries[engagementsPath][0].Get("product"))
	assert.Equal(t, "trivy-operator", l.queries[engagementsPath][0].Get("name"))

	require.Len(t, l.queries[testsPath], 2, "two pages")

	for _, q := range l.queries[testsPath] {
		assert.Equal(t, "21", q.Get("engagement"), "the engagement whose name is exactly the requested one")
		assert.Equal(t, "Trivy Operator Scan", q.Get("scan_type"))
	}
}

func TestClient_ListTests_MarksTheTestsOfTheLastEngagementWithTheName(t *testing.T) {
	engagements := []any{
		map[string]any{"id": 20, "name": "trivy-operator"},
		map[string]any{"id": 22, "name": "trivy-operator"},
		map[string]any{"id": 21, "name": "trivy-operator-extra"},
	}
	tests := map[string][]any{
		"20": {map[string]any{"id": 1, "title": "a", "scan_type": ScanTypeTrivyOperator}},
		"22": {
			map[string]any{"id": 5, "title": "a", "scan_type": ScanTypeTrivyOperator},
			map[string]any{"id": 6, "title": "b", "scan_type": ScanTypeTrivyOperator},
		},
	}

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		results := engagements
		if r.URL.Path == testsPath {
			results = tests[r.URL.Query().Get("engagement")]
		}

		writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": results})
	})

	listed, err := c.ListTests(context.Background(), Product{ID: 9, Name: "a/ns"}, "trivy-operator")

	require.NoError(t, err)

	last := map[int]bool{}
	for _, test := range listed {
		last[test.ID] = test.LastEngagement
	}

	assert.Equal(t, map[int]bool{1: false, 5: true, 6: true}, last,
		"a reimport writes into the last engagement with the name: the one with the highest ID")
}

func TestClient_ListTests_NoTestIsMarkedWhenTheLastEngagementHasNone(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		results := []any{
			map[string]any{"id": 20, "name": "trivy-operator"},
			map[string]any{"id": 23, "name": "trivy-operator"},
		}

		if r.URL.Path == testsPath {
			results = nil
			if r.URL.Query().Get("engagement") == "20" {
				results = []any{map[string]any{"id": 1, "title": "a", "scan_type": ScanTypeTrivyOperator}}
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": results})
	})

	listed, err := c.ListTests(context.Background(), Product{ID: 9, Name: "a/ns"}, "trivy-operator")

	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.False(t, listed[0].LastEngagement, "a reimport would create a test in the empty last engagement")
}

func TestClient_ListTests_NoEngagement(t *testing.T) {
	l := newListingServer(t, map[string][]any{engagementsPath: {}})
	c := newTestClient(t, l.handle)

	tests, err := c.ListTests(context.Background(), Product{ID: 9, Name: "a/ns"}, "trivy-operator")

	require.NoError(t, err)
	assert.Empty(t, tests)
	assert.Empty(t, l.queries[testsPath])
}

func TestClient_ListTests_ServerError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})

	_, err := c.ListTests(context.Background(), Product{ID: 9, Name: "a/ns"}, "trivy-operator")

	var apiErr *APIError

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadGateway, apiErr.StatusCode)
}

func TestClient_SetProductTags_PatchesTheFullList(t *testing.T) {
	var (
		method string
		path   string
		body   map[string]any
	)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path

		assert.Equal(t, "Token "+testToken, r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))

		writeJSON(w, http.StatusOK, map[string]any{})
	})

	require.NoError(t, c.SetProductTags(context.Background(), 9, []string{"owner:team", "k8s-cluster:a", "k8s-namespace:ns"}))

	assert.Equal(t, http.MethodPatch, method)
	assert.Equal(t, "/api/v2/products/9/", path)
	assert.Equal(t, map[string]any{"tags": []any{"owner:team", "k8s-cluster:a", "k8s-namespace:ns"}}, body)
}

func TestClient_SetProductTags_ServerError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	var apiErr *APIError

	require.ErrorAs(t, c.SetProductTags(context.Background(), 9, []string{"a:b"}), &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}

func TestClient_CloseTest_WaitsForTheReimportOfTheSameTest(t *testing.T) {
	var (
		mu       sync.Mutex
		inFlight int
		overlap  bool
	)

	enter := func() {
		mu.Lock()
		defer mu.Unlock()

		inFlight++
		overlap = overlap || inFlight > 1
	}

	leave := func() {
		mu.Lock()
		defer mu.Unlock()

		inFlight--
	}

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": []map[string]any{{"id": 1}}})

			return
		}

		enter()

		defer leave()

		time.Sleep(30 * time.Millisecond)

		writeJSON(w, http.StatusCreated, map[string]any{
			"test_id":    42,
			"statistics": map[string]any{"after": map[string]any{"total": map[string]any{"active": 0}}},
		})
	})

	req := testRequest()
	req.Product = closableTest.Product
	req.Engagement = closableTest.Engagement
	req.TestTitle = closableTest.Title

	_, err := c.Reimport(context.Background(), req)
	require.NoError(t, err)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		_, reimportErr := c.Reimport(context.Background(), req)
		assert.NoError(t, reimportErr)
	}()

	go func() {
		defer wg.Done()

		assert.NoError(t, closeErr(context.Background(), c, closableTest))
	}()

	wg.Wait()

	assert.False(t, overlap, "the close call and the reimport of one test never run at the same time")
}

func TestClient_CloseTest_OtherTestsDoNotWait(t *testing.T) {
	release := make(chan struct{})
	reached := make(chan struct{}, 1)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet && r.URL.Path == findingsPath) || r.Method == http.MethodPatch {
			writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": []map[string]any{}})

			return
		}

		reached <- struct{}{}

		<-release

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 1})
	})

	req := testRequest()

	go func() { _, _ = c.Reimport(context.Background(), req) }()

	<-reached

	other := Test{ID: 7, Title: "another", Product: req.Product, Engagement: req.Engagement}
	closeTest(t, c, other)

	close(release)
}

func TestListAll_NilFilter(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, strconv.Itoa(pageSize), r.URL.Query().Get("limit"))
		assert.Equal(t, "0", r.URL.Query().Get("offset"))

		writeJSON(w, http.StatusOK, map[string]any{"next": nil, "results": []Test{{ID: 7}}})
	})

	var got []Test

	err := listAll(context.Background(), c, testsPath, "tests", nil, func(test Test) { got = append(got, test) })

	require.NoError(t, err)
	assert.Equal(t, []Test{{ID: 7}}, got)
}
