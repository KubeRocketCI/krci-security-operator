package trivy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

// A test listed through the client and the request built for its report must name the same test, or the close
// and the reimport of the test do not wait for each other.
func TestImport_ReimportAndCloseOfTheListedTestShareALock(t *testing.T) {
	imp := NewReimport(testTarget(), KindVulnerabilityReport, loadFixture(t, "vulnerabilityreport_replicaset.json"),
		Workload{"deployment", "test-go-app"}, "go-app", Image{Name: "gitlab.127.0.0.1.nip.io:5050/krci/test-go-app"})

	var (
		mu                   sync.Mutex
		reimporting          bool
		findingsDuringImport bool
		startedOnce          sync.Once
	)

	started := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		page := func(results ...map[string]any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"next": nil, "results": results})
		}

		switch {
		case r.URL.Path == "/api/v2/reimport-scan/":
			mu.Lock()
			reimporting = true
			mu.Unlock()

			// The first request is the upload; the close of the test sends the second one.
			startedOnce.Do(func() {
				close(started)
				time.Sleep(100 * time.Millisecond)
			})

			mu.Lock()
			reimporting = false
			mu.Unlock()

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"test_id":    42,
				"statistics": map[string]any{"after": map[string]any{"total": map[string]any{"active": 0}}},
			})
		case r.URL.Path == "/api/v2/engagements/":
			page(map[string]any{"id": 21, "name": imp.Engagement})
		case r.URL.Path == "/api/v2/tests/":
			page(map[string]any{"id": 42, "title": imp.TestTitle, "scan_type": defectdojo.ScanTypeTrivyOperator})
		case strings.HasPrefix(r.URL.Path, "/api/v2/findings/"), r.Method == http.MethodPatch:
			mu.Lock()
			findingsDuringImport = findingsDuringImport || reimporting
			mu.Unlock()

			if r.Method == http.MethodGet {
				page(map[string]any{"id": 1, "service": "other"})

				return
			}

			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	ctx := context.Background()
	c := defectdojo.New().WithCredentials(srv.URL, "token")

	tests, err := c.ListTests(ctx, defectdojo.Product{ID: 9, Name: imp.Product}, imp.Engagement)
	require.NoError(t, err)
	require.Len(t, tests, 1)

	done := make(chan error, 1)

	go func() {
		_, reimportErr := c.Reimport(ctx, imp.Request("KubeRocketCI", time.Now(), "", []byte("{}")))
		done <- reimportErr
	}()

	<-started

	_, err = c.CloseTest(ctx, tests[0])
	require.NoError(t, err)
	require.NoError(t, <-done)

	assert.False(t, findingsDuringImport, "the close of the listed test waited for the reimport of its report")
}
