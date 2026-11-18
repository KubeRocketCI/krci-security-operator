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
	}, fields, "the form has the service, the version and one tags field per tag, and no apply_tags_to_findings")
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

// findingsServer serves the active findings of test 42 page by page and records the closed ones.
type findingsServer struct {
	t      *testing.T
	mu     sync.Mutex
	active []map[string]any
	closed []int
	bodies []map[string]any
	posts  atomic.Int32
	failOn int32
}

func (f *findingsServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	assert.Equal(f.t, "Token "+testToken, r.Header.Get("Authorization"))

	if r.Method == http.MethodGet {
		assert.Equal(f.t, "/api/v2/findings/", r.URL.Path)
		assert.Equal(f.t, "42", r.URL.Query().Get("test"))
		assert.Equal(f.t, "true", r.URL.Query().Get("active"))
		assert.Equal(f.t, "false", r.URL.Query().Get("is_mitigated"))

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
		f.active = append(f.active, map[string]any{"id": i + 1, "service": s})
	}

	return f
}

var closableTest = Test{ID: 42, Title: "VulnerabilityReport deployment/app/app", Product: "a/ns", Engagement: "trivy-operator"}

func TestClient_CloseTest_ClosesEveryActiveFinding(t *testing.T) {
	services := make([]string, 250)
	f := newFindingsServer(t, services...)
	c := newTestClient(t, f.handle)

	require.NoError(t, c.CloseTest(context.Background(), closableTest))

	assert.Len(t, f.closed, 250, "findings of every page are closed")
	assert.Empty(t, f.active)
	require.Len(t, f.bodies, 250)

	for _, b := range f.bodies {
		assert.Equal(t, true, b["is_mitigated"])

		mitigated, ok := b["mitigated"].(string)
		require.True(t, ok)

		_, err := time.Parse(time.RFC3339, mitigated)
		require.NoError(t, err)
		assert.True(t, strings.HasSuffix(mitigated, "Z"))
	}
}

func TestClient_CloseTest_NoActiveFindings(t *testing.T) {
	f := newFindingsServer(t)
	c := newTestClient(t, f.handle)

	require.NoError(t, c.CloseTest(context.Background(), closableTest))
	assert.Zero(t, f.posts.Load())
}

func TestClient_CloseTest_RetriesClose(t *testing.T) {
	f := newFindingsServer(t, "a")
	f.failOn = 1
	c := newTestClient(t, f.handle)

	require.NoError(t, c.CloseTest(context.Background(), closableTest))

	assert.Equal(t, []int{1}, f.closed)
	assert.Equal(t, int32(2), f.posts.Load(), "the 503 was retried")
}

func TestClient_CloseTest_ServerError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	var apiErr *APIError

	require.ErrorAs(t, c.CloseTest(context.Background(), closableTest), &apiErr)
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

			require.ErrorIs(t, c.CloseTest(context.Background(), test), ErrTestNotNamed)

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
			map[string]any{"id": 1, "title": "a", "scan_type": ScanTypeTrivyOperator, "tags": []string{"k8s-workload:x"}},
			map[string]any{"id": 2, "title": "b", "scan_type": ScanTypeTrivyOperator, "tags": []string{}},
			map[string]any{"id": 3, "title": "c", "scan_type": "Trivy Scan"},
		},
	})
	c := newTestClient(t, l.handle)

	tests, err := c.ListTests(context.Background(), Product{ID: 9, Name: "a/ns"}, "trivy-operator")

	require.NoError(t, err)
	assert.Equal(t, []Test{
		{ID: 1, Title: "a", ScanType: ScanTypeTrivyOperator, Tags: []string{"k8s-workload:x"}, Product: "a/ns", Engagement: "trivy-operator"},
		{ID: 2, Title: "b", ScanType: ScanTypeTrivyOperator, Tags: []string{}, Product: "a/ns", Engagement: "trivy-operator"},
		{ID: 3, Title: "c", ScanType: "Trivy Scan", Product: "a/ns", Engagement: "trivy-operator"},
	}, tests, "scan type and tags are the ones of the response, also when the server ignores the scan type filter")

	require.Len(t, l.queries[engagementsPath], 1)
	assert.Equal(t, "9", l.queries[engagementsPath][0].Get("product"))
	assert.Equal(t, "trivy-operator", l.queries[engagementsPath][0].Get("name"))

	require.Len(t, l.queries[testsPath], 2, "two pages")

	for _, q := range l.queries[testsPath] {
		assert.Equal(t, "21", q.Get("engagement"), "the engagement whose name is exactly the requested one")
		assert.Equal(t, "Trivy Operator Scan", q.Get("scan_type"))
	}
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

		writeJSON(w, http.StatusCreated, ReimportResult{TestID: 42})
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

		assert.NoError(t, c.CloseTest(context.Background(), closableTest))
	}()

	wg.Wait()

	assert.False(t, overlap, "the close call and the reimport of one test never run at the same time")
}

func TestClient_CloseTest_OtherTestsDoNotWait(t *testing.T) {
	release := make(chan struct{})
	reached := make(chan struct{}, 1)

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == findingsPath {
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
	require.NoError(t, c.CloseTest(context.Background(), other))

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
