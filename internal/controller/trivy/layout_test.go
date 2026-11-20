package trivy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const secretsTitle = "ExposedSecretReport deployment/test-go-app/test-go-app"

func TestReconcile_ImportsIntoTheNamespaceProduct(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))

	res := h.reconcile()

	assert.Equal(t, resync, res.RequeueAfter)
	require.Len(t, h.dd.reimports, 2)

	vuln := h.byTitle()[goAppTitle]
	assert.Equal(t, "KubeRocketCI", vuln.ProductType)
	assert.Equal(t, "in-cluster/krci-demo-dev", vuln.Product)
	assert.Equal(t, "trivy-operator", vuln.Engagement)

	secrets := h.byTitle()[secretsTitle]
	assert.Equal(t, "KubeRocketCI", secrets.ProductType)
	assert.Equal(t, "in-cluster/krci-demo-dev", secrets.Product)
	assert.Equal(t, "trivy-operator", secrets.Engagement)

	for _, id := range h.dd.testIDs() {
		assert.Equal(t, goAppContext, h.dd.contextOf(id), "both report kinds go to one product and one engagement")
	}

	productTypes, products, engagements := h.dd.counts()
	assert.Equal(t, [3]int{1, 1, 1}, [3]int{productTypes, products, engagements})
}

func TestReconcile_ImportsUnderTheConfiguredProductType(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconciler.config.ProductType = "Acme"

	h.reconcile()

	require.Len(t, h.dd.testIDs(), 1)

	want := goAppContext
	want.productType = "Acme"

	assert.Equal(t, want, h.dd.contextOf(h.dd.testIDs()[0]))
}

func TestReconcile_SameNamespaceOfTwoClustersGivesTwoProducts(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	cfg := baseConfig()
	cfg.ClusterName = "prod-eu"

	other := NewReconciler(h.client, h.client, cfg, h.reconciler.watched, func(string, string) DefectDojo { return h.dd })
	other.now = h.reconciler.now
	other.random = h.reconciler.random

	h.reconcile()

	_, err := other.Reconcile(context.Background(), namespaceRequest(appNS))
	require.NoError(t, err)

	ids := h.dd.testIDs()
	require.Len(t, ids, 2, "each cluster has its own test")

	products := []string{h.dd.contextOf(ids[0]).product, h.dd.contextOf(ids[1]).product}
	assert.ElementsMatch(t, []string{"in-cluster/krci-demo-dev", "prod-eu/krci-demo-dev"}, products)
	assert.Equal(t, h.dd.contextOf(ids[0]).engagement, h.dd.contextOf(ids[1]).engagement)

	_, productCount, _ := h.dd.counts()
	assert.Equal(t, 2, productCount)
}

// stageLikeObjects is the KubeRocketCI data of a namespace: the tenant label and a Stage that points at it.
func stageLikeObjects() []client.Object {
	stage := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"cdPipeline": "demo", "name": "dev", "namespace": appNS, "clusterName": "in-cluster",
	}}}
	stage.SetAPIVersion("v2.edp.epam.com/v1")
	stage.SetKind("Stage")
	stage.SetName("demo-dev")
	stage.SetNamespace("krci")

	ns := namespaceObject(appNS, map[string]string{"app.edp.epam.com/tenant": "krci"})

	return []client.Object{integrationSecret(), ns, stage, deployment("test-go-app", "1"),
		replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1")}
}

func TestReconcile_KubeRocketCIResourcesAndLabelsChangeNothing(t *testing.T) {
	plain := newHarness(t, withReports(goAppObjects(), goApp(t)))
	plain.reconcile()

	var touched []string

	record := func(group string) {
		if group == "v2.edp.epam.com" {
			touched = append(touched, group)
		}
	}

	krci := newHarness(t, withReports(stageLikeObjects(), goApp(t)), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if gvk, err := apiutil.GVKForObject(list, c.Scheme()); err == nil {
				record(gvk.Group)
			}

			return c.List(ctx, list, opts...)
		},
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			record(obj.GetObjectKind().GroupVersionKind().Group)

			return c.Get(ctx, key, obj, opts...)
		},
	})
	krci.reconcile()

	require.Len(t, krci.dd.reimports, 1)
	require.Len(t, plain.dd.reimports, 1)
	assert.Equal(t, plain.dd.reimports[0], krci.dd.reimports[0], "the same request with and without KubeRocketCI data")
	assert.Empty(t, touched, "no KubeRocketCI resource is read")
}

func TestReconcile_ExcludedNamespaceClosesItsOwnedTestsOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns []string
	}{
		{name: "glob", patterns: []string{"kube-*", "krci-demo-*"}},
		{name: "name", patterns: []string{appNS}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), goApp(t)))
			h.reconciler.config.ExcludeNamespaces = tc.patterns
			h.dd.seedTests(ownedTest(1, goAppTitle))
			h.dd.seedNamespace("other", appNS, ownedTest(2, goAppTitle))

			res := h.reconcile()

			assert.Equal(t, resync, res.RequeueAfter)
			assert.Empty(t, h.dd.reimports)
			assert.Equal(t, []int{1}, h.dd.closed)

			h.reconcile()
			assert.Equal(t, []int{1}, h.dd.closed, "the tests are closed once")
		})
	}
}

func TestReconcile_ReturningFromExclusionImportsAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.reconciler.config.ExcludeNamespaces = []string{appNS}

	h.reconcile()
	assert.Equal(t, []int{100}, h.dd.closed)

	h.reconciler.config.ExcludeNamespaces = nil

	h.reconcile()
	assert.Len(t, h.dd.reimports, 2, "the closed test is reimported")

	h.reconciler.config.ExcludeNamespaces = []string{appNS}

	h.reconcile()
	assert.Equal(t, []int{100, 100}, h.dd.closed)
}

func TestReconcile_ReleasePrunesTheNamespaceAndImportingForgetsIt(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Contains(t, h.reconciler.reimported, appNS)

	h.reconciler.config.ExcludeNamespaces = []string{appNS}

	h.reconcile()
	assert.True(t, h.reconciler.isReleased(appNS))
	assert.NotContains(t, h.reconciler.reimported, appNS)
	assert.NotContains(t, h.reconciler.closed, appNS)

	h.reconciler.config.ExcludeNamespaces = nil

	h.reconcile()
	assert.False(t, h.reconciler.isReleased(appNS), "an imported namespace is no longer released")
}

func TestRelease_OnlyOwnedTests(t *testing.T) {
	h := newHarness(t, goAppObjects())

	title := "VulnerabilityReport deployment/a/a"

	h.dd.seedNamespace("other", appNS, ownedTest(5, title))
	h.dd.seedNamespace("x-"+cluster, appNS, ownedTest(6, title))
	h.dd.seedScanTest(goAppContext, "Trivy Scan", ownedTest(7, title))

	require.NoError(t, h.reconciler.release(context.Background(), h.dd, appNS))
	assert.Empty(t, h.dd.closed, "no test of another cluster, another prefix or another scan type is closed")

	h.reconciler.markImportable(appNS)
	h.dd.seedTests(ownedTest(10, title))

	require.NoError(t, h.reconciler.release(context.Background(), h.dd, appNS))
	assert.Equal(t, []int{10}, h.dd.closed)
}

func TestReconcile_ExcludedNamespaceIsNotReadForReports(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if isReportList(list) {
				return errors.New("an excluded namespace lists no reports")
			}

			return c.List(ctx, list, opts...)
		},
	})
	h.reconciler.config.ExcludeNamespaces = []string{appNS}

	h.reconcile()

	assert.Empty(t, h.dd.reimports)
}

func TestImportableNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		excluded  []string
		want      bool
	}{
		{name: "live namespace", namespace: appNS, want: true},
		{name: "missing namespace", namespace: "missing"},
		{name: "terminating namespace", namespace: "terminating"},
		{name: "excluded by a glob", namespace: appNS, excluded: []string{"krci-*"}},
		{name: "glob that does not match", namespace: appNS, excluded: []string{"kube", "*-public"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			terminating := namespaceObject("terminating", nil)
			terminating.DeletionTimestamp = &metav1.Time{Time: scanDate}
			terminating.Finalizers = []string{"kubernetes"}

			h := newHarness(t, []client.Object{namespaceObject(appNS, nil), terminating})
			h.reconciler.config.ExcludeNamespaces = tt.excluded

			got, err := h.reconciler.importableNamespace(context.Background(), tt.namespace)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got != nil)

			if tt.want {
				assert.Equal(t, tt.namespace, got.Name)
			}
		})
	}
}
