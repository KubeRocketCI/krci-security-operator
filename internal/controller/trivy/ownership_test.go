package trivy

import (
	"context"
	"maps"
	"slices"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

const (
	goAppProduct = "in-cluster/krci-demo-dev"

	findingKept  = "CVE-2026-14456 libcrypto3 3.5.6-r0"
	findingFixed = "CVE-2026-45447 libcrypto3 3.5.6-r0"
)

// bothActive is the state of the findings of the go app after an import.
var bothActive = map[string]string{findingKept: statusActive, findingFixed: statusActive}

// bothClosed is the state of the findings of the go app after its test was closed.
var bothClosed = map[string]string{findingKept: statusClosed, findingFixed: statusClosed}

// importedGoApp imports the go app and returns the ID of its test.
func importedGoApp(t *testing.T, h *harness) int {
	t.Helper()

	h.reconcile()

	ids := h.dd.testIDs()
	require.Len(t, ids, 1)
	require.Equal(t, bothActive, h.dd.statuses(ids[0], goAppService))

	return ids[0]
}

func TestReconcile_DeletedNamespaceClosesTheFindingsAndKeepsProductAndTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := importedGoApp(t, h)

	h.remove(namespaceObject(appNS, nil))

	h.reconcile()

	assert.Equal(t, bothClosed, h.dd.statuses(testID, goAppService))
	assert.Equal(t, []int{testID}, h.dd.testIDs(), "the test stays")
	assert.True(t, h.dd.hasProduct(goAppProduct), "the product stays")
}

func TestReconcile_ExcludedNamespaceClosesTheFindingsAndKeepsProductAndTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := importedGoApp(t, h)

	h.reconciler.config.ExcludeNamespaces = []string{appNS}

	h.reconcile()

	assert.Equal(t, bothClosed, h.dd.statuses(testID, goAppService))
	assert.Equal(t, []int{testID}, h.dd.testIDs(), "the test stays")
	assert.True(t, h.dd.hasProduct(goAppProduct), "the product stays")
}

func TestReconcile_NeverClosesTheTestsOfAnotherClusterWithTheSameNamespaceName(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	cfg := baseConfig()
	cfg.ClusterName = "prod-eu"

	prod := NewReconciler(h.client, h.client, cfg, func(string, string) DefectDojo { return h.dd })
	prod.now = h.reconciler.now
	prod.random = h.reconciler.random

	h.reconcile()

	_, err := prod.Reconcile(context.Background(), namespaceRequest(appNS))
	require.NoError(t, err)

	ids := h.dd.testIDs()
	require.Len(t, ids, 2)

	// The operator of in-cluster releases the namespace; prod-eu still imports it.
	h.reconciler.config.ExcludeNamespaces = []string{appNS}

	h.reconcile()

	for _, id := range ids {
		wantClosed := h.dd.contextOf(id).product == goAppProduct

		want := bothActive
		if wantClosed {
			want = bothClosed
		}

		assert.Equal(t, want, h.dd.statuses(id, goAppService), h.dd.contextOf(id).product)
	}
}

func TestReconcile_ReimportNeverReachesTheTestOfAnotherClusterWithTheSameTitle(t *testing.T) {
	const (
		otherService = "krci-demo-dev/ReplicaSet/test-go-app-old/test-go-app"
		otherFinding = "CVE-2026-14456 libcrypto3 3.5.6-r0"
	)

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedNamespace("prod-eu", appNS, ownedTest(200, goAppTitle))
	h.dd.seedFinding(200, otherFinding, otherService)

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, goAppProduct, h.dd.reimports[0].Product)
	assert.Equal(t, map[string]string{otherFinding: statusActive}, h.dd.statuses(200, otherService),
		"the finding of another cluster stays active")
}

func TestReconcile_ProductThatOnlyContainsTheClusterPrefixIsNotOwned(t *testing.T) {
	h := newHarness(t, goAppObjects())

	// "x-in-cluster/krci-demo-dev" contains "in-cluster/" but does not start with it.
	other := namespaceContext("x-"+cluster, appNS)
	h.dd.seedTestsIn(other, anyTest(5))
	h.dd.seedFinding(5, "CVE-2026-1 pkg 1.0", "krci-demo-dev/Deployment/a/a")

	h.remove(namespaceObject(appNS, nil))

	h.reconcile()

	assert.Empty(t, h.dd.closed)
	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusActive}, h.dd.statuses(5, "krci-demo-dev/Deployment/a/a"))

	require.NoError(t, h.reconciler.sweep(context.Background()))
	assert.Empty(t, wakes(h), "the sweep does not take its namespace for one of this cluster")
}

func TestReconcile_TestOfAnotherScanTypeInTheNamespaceProductIsNotClosed(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.dd.seedScanTest(goAppContext, "Trivy Scan", defectdojo.Test{ID: 5, Title: "VulnerabilityReport deployment/a/a"})
	h.dd.seedFinding(5, "CVE-2026-1 pkg 1.0", "svc")

	h.remove(namespaceObject(appNS, nil))

	h.reconcile()

	assert.Empty(t, h.dd.closed)
	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusActive}, h.dd.statuses(5, "svc"))
}

func TestReconcile_ClosesOnlyTheTestsOfItsNamespaceProduct(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedNamespace(cluster, "krci-demo-qa", anyTest(5))
	h.dd.seedFinding(5, "CVE-2026-1 pkg 1.0", "svc")

	h.reconcile()

	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusActive}, h.dd.statuses(5, "svc"),
		"a live namespace closes no test of another namespace")

	h.remove(namespaceObject(appNS, nil))

	h.reconcile()

	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusActive}, h.dd.statuses(5, "svc"),
		"the tests of another namespace product stay open")
}

func TestReconcile_NewProductGetsItsTags(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()

	assert.ElementsMatch(t, []string{"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"}, h.dd.productTags(goAppProduct))
	require.Len(t, h.dd.tagCalls, 1)

	h.setReport(goApp(t))

	h.reconcile()
	assert.Len(t, h.dd.tagCalls, 1, "a product that has its tags is not patched again")
}

func TestReconcile_ProductTagsKeepTheOtherTags(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTests(ownedTest(100, goAppTitle))
	h.dd.seedProductTags(goAppProduct, "owner:payments", "k8s-namespace:old")

	h.reconcile()

	assert.ElementsMatch(t, []string{"owner:payments", "k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"},
		h.dd.productTags(goAppProduct), "the full list is sent: the other tags stay, a wrong value is replaced")
}

func TestReconcile_ProductWithItsTagsIsNotPatched(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTests(ownedTest(100, goAppTitle))
	h.dd.seedProductTags(goAppProduct, "k8s-namespace:krci-demo-dev", "k8s-cluster:in-cluster")

	h.reconcile()

	assert.Equal(t, []string{"k8s-namespace:krci-demo-dev", "k8s-cluster:in-cluster"}, h.dd.productTags(goAppProduct),
		"the tag list is unchanged")
	assert.Empty(t, h.dd.tagCalls)
}

func TestReconcile_FailedTagUpdateIsRetriedAndDoesNotBlockClosing(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTests(ownedTest(5, "VulnerabilityReport deployment/removed/removed"))
	h.dd.tagErr = &defectdojo.APIError{StatusCode: 500}

	require.Error(t, h.reconcileErr())
	assert.Equal(t, []int{5}, h.dd.closed, "the stale test is closed although the tags failed")
	assert.Empty(t, h.dd.productTags(goAppProduct))

	h.dd.tagErr = nil

	h.reconcile()

	assert.ElementsMatch(t, []string{"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"}, h.dd.productTags(goAppProduct),
		"the next pass repairs the tags although no report changed")
}

func TestSweep_WakesTheNamespaceOfAProductWithWrongTagsAndWritesNothing(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.NotEmpty(t, h.dd.productTags(goAppProduct))

	// A product edited by hand, or tags lost on a restart of DefectDojo.
	h.dd.seedProductTags(goAppProduct, "owner:payments")
	calls := len(h.dd.tagCalls)

	require.NoError(t, h.reconciler.sweep(context.Background()))

	assert.Equal(t, []string{appNS}, wakes(h), "the namespace is woken although it is live and imported")
	assert.Len(t, h.dd.tagCalls, calls, "the sweeper writes nothing")
	assert.Equal(t, []string{"owner:payments"}, h.dd.productTags(goAppProduct))

	h.reconcile()

	assert.ElementsMatch(t, []string{"owner:payments", "k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"},
		h.dd.productTags(goAppProduct), "the controller repairs the tags of the woken namespace")
}

func TestSweep_DoesNotWakeALiveNamespaceWithItsTags(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()

	require.NoError(t, h.reconciler.sweep(context.Background()))
	assert.Empty(t, wakes(h))
}

func TestSweep_WakesAReleasedNamespaceWithWrongTagsAndTheControllerKeepsItsClosedTests(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := importedGoApp(t, h)

	h.remove(namespaceObject(appNS, nil))
	h.reconcile()
	require.Equal(t, bothClosed, h.dd.statuses(testID, goAppService))

	h.dd.seedProductTags(goAppProduct, "owner:payments")

	require.NoError(t, h.reconciler.sweep(context.Background()))
	require.Equal(t, []string{appNS}, wakes(h))

	closed := len(h.dd.closed)

	h.reconcile()

	assert.ElementsMatch(t, []string{"owner:payments", "k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"},
		h.dd.productTags(goAppProduct))
	assert.Len(t, h.dd.closed, closed, "the tests of a released namespace are closed once")
}

func TestReconcile_GoneOrExcludedNamespaceRepairsTheTagsOfItsProduct(t *testing.T) {
	for name, leave := range map[string]func(h *harness){
		"gone":     func(h *harness) { h.remove(namespaceObject(appNS, nil)) },
		"excluded": func(h *harness) { h.reconciler.config.ExcludeNamespaces = []string{appNS} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), goApp(t)))
			testID := importedGoApp(t, h)
			h.dd.seedProductTags(goAppProduct, "owner:payments")

			leave(h)
			h.reconcile()

			assert.Equal(t, bothClosed, h.dd.statuses(testID, goAppService))
			assert.ElementsMatch(t, []string{"owner:payments", "k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"},
				h.dd.productTags(goAppProduct))
		})
	}
}

func TestReconcile_FailedTagUpdateOfAReleasedNamespaceIsRetriedWithoutClosingAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := importedGoApp(t, h)
	h.dd.seedProductTags(goAppProduct, "owner:payments")
	h.dd.tagErr = &defectdojo.APIError{StatusCode: 500}

	h.remove(namespaceObject(appNS, nil))

	require.Error(t, h.reconcileErr())
	assert.Equal(t, bothClosed, h.dd.statuses(testID, goAppService), "the tests are closed although the tags failed")
	assert.True(t, h.reconciler.isReleased(appNS))

	h.dd.tagErr = nil
	closed := len(h.dd.closed)

	h.reconcile()

	assert.ElementsMatch(t, []string{"owner:payments", "k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev"},
		h.dd.productTags(goAppProduct))
	assert.Len(t, h.dd.closed, closed)
}

func TestSweep_WakesOnlyTheProductsOfItsCluster(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedNamespace("other", appNS, anyTest(5))
	h.dd.seedNamespace("x-"+cluster, appNS, anyTest(6))
	h.dd.seedTestsIn(ddContext{productType: "KubeRocketCI", product: "in-cluster", engagement: "image:x"}, anyTest(7))

	require.NoError(t, h.reconciler.sweep(context.Background()))

	assert.Empty(t, wakes(h), "no product of another cluster, another prefix or the CI pipeline is woken")
	assert.Empty(t, h.dd.tagCalls)
}

// unfilteredScanTypes is a DefectDojo that ignores the scan type filter of the tests list.
type unfilteredScanTypes struct{ *fakeDefectDojo }

func (d unfilteredScanTypes) ListTests(
	_ context.Context,
	product defectdojo.Product,
	engagement string,
) ([]defectdojo.Test, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []defectdojo.Test

	for _, id := range slices.Sorted(maps.Keys(d.tests)) {
		test := d.tests[id]
		if e := d.engagements[test.engagement]; e.product == product.ID && e.name == engagement {
			out = append(out, defectdojo.Test{
				ID: test.id, Title: test.title, ScanType: test.scanType, Product: product.Name, Engagement: engagement,
			})
		}
	}

	return out, nil
}

func TestReconcile_ScanTypeOfTheResponseDecidesOwnership(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.reconciler.connect = func(string, string) DefectDojo { return unfilteredScanTypes{h.dd} }

	h.dd.seedTests(anyTest(4))
	h.dd.seedScanTest(goAppContext, "Trivy Scan", defectdojo.Test{ID: 5, Title: "VulnerabilityReport deployment/a/a"})
	h.dd.seedFinding(4, "CVE-2026-1 pkg 1.0", "svc")
	h.dd.seedFinding(5, "CVE-2026-1 pkg 1.0", "svc")

	h.remove(namespaceObject(appNS, nil))

	h.reconcile()

	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusClosed}, h.dd.statuses(4, "svc"))
	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusActive}, h.dd.statuses(5, "svc"),
		"a test of another scan type is not closed when the list returns it")
}

func TestReconcile_ReleaseWithoutTheProductTypeIsRetriedNotMarked(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.remove(namespaceObject(appNS, nil))

	var lines []string

	log := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})
	ctx := ctrl.LoggerInto(context.Background(), log)

	// DefectDojo lists no Product Type: the namespace may have tests that the lookup cannot see.
	for range 2 {
		_, err := h.reconciler.Reconcile(ctx, namespaceRequest(appNS))
		require.NoError(t, err)
	}

	assert.False(t, h.reconciler.isReleased(appNS), "the release is not recorded")
	assert.Len(t, lines, 1, "the missing Product Type is logged once per process")
	assert.Contains(t, lines[0], "Product Type")

	h.dd.seedTests(anyTest(5))
	h.dd.seedFinding(5, "CVE-2026-1 pkg 1.0", "svc")

	_, err := h.reconciler.Reconcile(ctx, namespaceRequest(appNS))
	require.NoError(t, err)

	assert.True(t, h.reconciler.isReleased(appNS))
	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusClosed}, h.dd.statuses(5, "svc"),
		"the next pass closes the tests once the Product Type is listed")
}

func TestReconcile_ProductOfAnotherCaseIsNotTheNamespaceProduct(t *testing.T) {
	h := newHarness(t, goAppObjects())

	// DefectDojo matches the exact name without regard to case.
	h.dd.seedNamespace("IN-CLUSTER", appNS, anyTest(5))
	h.dd.seedFinding(5, "CVE-2026-1 pkg 1.0", "svc")

	h.remove(namespaceObject(appNS, nil))

	h.reconcile()

	assert.Empty(t, h.dd.closed)
	assert.Equal(t, map[string]string{"CVE-2026-1 pkg 1.0": statusActive}, h.dd.statuses(5, "svc"))
}
