package ddcontract

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

// dojoAPI answers the reads of Live.Snapshot with fixed DefectDojo answers and records the writes.
type dojoAPI struct {
	mu     sync.Mutex
	writes []string
}

func (d *dojoAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	if r.Method != http.MethodGet {
		d.mu.Lock()
		d.writes = append(d.writes, r.Method+" "+r.URL.Path+" "+string(body))
		d.mu.Unlock()

		w.WriteHeader(http.StatusNoContent)

		return
	}

	answer, ok := d.answer(r)
	if !ok {
		http.NotFound(w, r)

		return
	}

	_, _ = io.WriteString(w, answer)
}

func (d *dojoAPI) answer(r *http.Request) (string, bool) {
	q := r.URL.Query()

	switch r.URL.Path {
	case "/api/v2/oa3/schema/":
		return `{"openapi":"3.0.3","info":{"title":"DefectDojo API v2","version":"3.5.200"},"paths":{}}`, true
	case "/api/v2/system_settings/":
		return `{"results":[{"enable_deduplication":true}]}`, true
	case "/api/v2/product_types/":
		return `{"next":null,"results":[{"id":5,"name":"` + q.Get("name") + `x"},{"id":6,"name":"` + q.Get("name") + `"}]}`, true
	case "/api/v2/products/":
		// The page size is capped at one product: the next page starts at the number read.
		if q.Get("offset") == "0" {
			return `{"next":"http://h/api/v2/products/?offset=1","results":[{"id":31,"name":"run/ns2","tags":[]}]}`, true
		}

		return `{"next":null,"results":[{"id":30,"name":"run/ns","tags":["b:1","a:1"]}]}`, true
	case "/api/v2/engagements/":
		if q.Get("product") == "30" {
			return `{"next":null,"results":[{"id":40,"name":"trivy-operator"}]}`, true
		}

		return `{"next":null,"results":[]}`, true
	case "/api/v2/tests/":
		return `{"next":null,"results":[{"id":50,"title":"t","scan_type":"Trivy Operator Scan","version":null,` +
			`"build_id":null,"tags":["k:1"]}]}`, true
	case "/api/v2/findings/":
		return `{"next":null,"results":[{"id":61,"title":"CVE-1 Libssl","severity":"High","service":null,` +
			`"hash_code":"h","active":false,"verified":false,"is_mitigated":true,"false_p":true,"risk_accepted":false,` +
			`"out_of_scope":false},{"id":60,"title":"CVE-2 Libssl","severity":"Low","service":"s","hash_code":"g",` +
			`"active":true}]}`, true
	case "/api/v2/test_imports/":
		return `{"next":null,"results":[{"id":71,"type":"reimport","test_import_finding_action_set":[` +
			`{"finding":60,"action":"U"},{"finding":61,"action":"C"},{"finding":62,"action":"R"},{"finding":63,"action":"N"}]},` +
			`{"id":70,"type":"import","test_import_finding_action_set":[{"finding":60,"action":"N"}]}]}`, true
	default:
		return "", false
	}
}

func TestLive_SnapshotReadsEveryPageAndNormalizes(t *testing.T) {
	srv := httptest.NewServer(&dojoAPI{})
	defer srv.Close()

	live := NewLive(srv.URL+"/", "t", "run")

	raw, err := live.Snapshot(context.Background(), "run")
	require.NoError(t, err)

	r := refs{}
	r.learn(raw)
	got := r.normalize(raw, "run")

	require.Len(t, got.Products, 2, "both pages are read")
	assert.Equal(t, "ddcontract/ns", got.Products[0].Name, "ID 30 is the first product")
	assert.Equal(t, []string{"b:1", "a:1"}, got.Products[0].Tags, "the tags keep the order of DefectDojo")
	assert.Equal(t, "ddcontract/ns2", got.Products[1].Name)
	assert.Empty(t, got.Products[1].Engagements)

	test := got.Products[0].Engagements[0].Tests[0]
	assert.Equal(t, TestState{
		Ref: 1, Title: "t", ScanType: "Trivy Operator Scan", Version: "", BuildID: "", Tags: []string{"k:1"},
		Findings: []FindingState{
			{Ref: 1, Title: "cve-2 libssl", Severity: "Low", Service: "s", Hash: "g", Active: true},
			{Ref: 2, Title: "cve-1 libssl", Severity: "High", Hash: "h", Mitigated: true, FalsePositive: true},
		},
		Imports: []ImportState{
			{Ref: 1, Type: ImportTypeImport, Created: []int{1}, Closed: []int{}, Reactivated: []int{}, Untouched: []int{}},
			{Ref: 2, Type: ImportTypeReimport, Created: []int{0}, Closed: []int{2}, Reactivated: []int{0}, Untouched: []int{1}},
		},
	}, test, "null fields are empty; a finding of no test has no ordinal")
}

func TestLive_SnapshotOfAMissingProductTypeIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"next":null,"results":[]}`)
	}))
	defer srv.Close()

	live := NewLive(srv.URL, "t", "run")

	got, err := live.Snapshot(context.Background(), "run")
	require.NoError(t, err)
	assert.Empty(t, got.Products)
	require.NoError(t, live.DeleteProductType(context.Background(), "run"), "nothing to delete")
}

func TestLive_WritesTheUserChangesAndReadsTheServer(t *testing.T) {
	api := &dojoAPI{}

	srv := httptest.NewServer(api)
	defer srv.Close()

	live := NewLive(srv.URL, "t", "run")
	ctx := context.Background()

	require.NoError(t, live.Triage(ctx, 7, TriageOutOfScope))
	require.NoError(t, live.AddEngagement(ctx, 30, "trivy-operator"))
	require.NoError(t, live.DeleteProductType(ctx, "run"))

	assert.Equal(t, []string{
		`PATCH /api/v2/findings/7/ {"active":false,"out_of_scope":true}`,
		`POST /api/v2/engagements/ {"name":"trivy-operator","product":30,"target_end":"2026-01-01","target_start":"2026-01-01"}`,
		`DELETE /api/v2/product_types/6/ `,
	}, api.writes)
	assert.Empty(t, live.TakeExchanges(), "only the client calls are recorded")

	server, err := live.ServerInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, Server{Version: "3.5.200", Deduplication: true}, server)
}

func TestLive_AnswerOver299IsAnAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := NewLive(srv.URL, "t", "run").Snapshot(context.Background(), "run")

	var apiErr *defectdojo.APIError

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
}

// failingBody fails every read and records its close.
type failingBody struct{ closed bool }

func (b *failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func (b *failingBody) Close() error {
	b.closed = true

	return nil
}

func TestRecordingTransport_ClosesARequestBodyItCannotRead(t *testing.T) {
	body := &failingBody{}
	req := httptest.NewRequest(http.MethodPost, "http://defectdojo/api/v2/reimport-scan/", body)

	_, err := (&recordingTransport{base: http.DefaultTransport}).RoundTrip(req)

	require.ErrorContains(t, err, "read the request body")
	assert.True(t, body.closed)
}
