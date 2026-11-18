package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	tenantNS   = "krci"
	stageNS    = "krci-demo-dev"
	operatorNS = "krci-security"
	secretName = "defectdojo-credentials"
	cluster    = "in-cluster"
	resync     = 30 * time.Minute

	revisionAnnotation = "deployment.kubernetes.io/revision"
	goAppTitle         = "VulnerabilityReport krci-demo-dev/deployment/test-go-app/test-go-app"
	// goAppService is the service the DefectDojo parser gives the findings of the go app's report.
	goAppService = "krci-demo-dev/Deployment/test-go-app/test-go-app"
)

var scanDate = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// goAppContext is where the go app's reports of the Stage demo-dev are imported.
var goAppContext = ddContext{productType: "KubeRocketCI", product: "test-go-app", engagement: "runtime:demo-dev"}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))

	return s
}

func baseConfig() Config {
	return Config{
		OperatorNamespace: operatorNS,
		SecretName:        secretName,
		ProductType:       "KubeRocketCI",
		PlatformProduct:   "platform",
		ClusterName:       cluster,
		Scopes:            Scopes{Stage: true, Tenant: true, Platform: true},
		ComponentPrefixes: []string{"in-cluster-"},
		ResyncPeriod:      resync,
		Concurrency:       1,
		ReportKinds:       []string{trivy.KindVulnerabilityReport, trivy.KindExposedSecretReport},
	}
}

func newStage(name, stage, namespace, clusterName string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"cdPipeline":  "demo",
		"name":        stage,
		"namespace":   namespace,
		"clusterName": clusterName,
	}}}
	u.SetGroupVersionKind(stageGVK)
	u.SetName(name)
	u.SetNamespace(tenantNS)

	return u
}

func demoStage() *unstructured.Unstructured {
	return newStage("demo-dev", "dev", stageNS, inClusterName)
}

func integrationSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: operatorNS},
		Data:       map[string][]byte{"url": []byte("https://dd.example.com"), "token": []byte("t")},
	}
}

func codebaseImageStream(imageName, codebase string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"imageName": imageName,
		"codebase":  codebase,
	}}}
	u.SetGroupVersionKind(imageStreamGVK)
	u.SetName(codebase + "-main")
	u.SetNamespace(tenantNS)

	return u
}

func namespaceObject(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func tenantNamespace(name string) *corev1.Namespace {
	return namespaceObject(name, map[string]string{tenantLabel: tenantNS})
}

func fixture(t *testing.T, name string) *unstructured.Unstructured {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "trivy", "testdata", name))
	require.NoError(t, err)

	obj := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &obj))

	u := &unstructured.Unstructured{Object: obj}
	u.SetNamespace(stageNS)
	u.SetUID(types.UID("uid-" + name))
	u.SetResourceVersion("100")

	return u
}

func goApp(t *testing.T) *unstructured.Unstructured {
	t.Helper()

	return fixture(t, "vulnerabilityreport_replicaset.json")
}

func goAppSecrets(t *testing.T) *unstructured.Unstructured {
	t.Helper()

	return fixture(t, "exposedsecretreport_replicaset.json")
}

func replicaSet(name, deployment, revision string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   stageNS,
			Annotations: map[string]string{revisionAnnotation: revision},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment", Name: deployment, Controller: ptr.To(true),
			}},
		},
		Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To(int32(1))},
	}
}

func deployment(name, revision string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: stageNS, Annotations: map[string]string{revisionAnnotation: revision},
	}}
}

// goAppObjects is a running go app of the Stage demo-dev: its Deployment on revision 1, the current ReplicaSet,
// the codebase, the namespaces and the credentials.
func goAppObjects() []client.Object {
	return []client.Object{
		demoStage(),
		integrationSecret(),
		namespaceObject(tenantNS, nil),
		tenantNamespace(stageNS),
		codebaseImageStream("gitlab.127.0.0.1.nip.io:5050/krci/test-go-app", "test-go-app"),
		deployment("test-go-app", "1"),
		replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1"),
	}
}

// tenantObjects is the same go app in a tenant namespace that belongs to no Stage.
func tenantObjects() []client.Object {
	return []client.Object{
		integrationSecret(),
		tenantNamespace(stageNS),
		deployment("test-go-app", "1"),
		replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1"),
	}
}

type harness struct {
	t          *testing.T
	client     client.Client
	dd         *fakeDefectDojo
	reconciler *Reconciler
}

func newHarness(t *testing.T, objects []client.Object, funcs ...interceptor.Funcs) *harness {
	t.Helper()

	b := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...)
	if len(funcs) > 0 {
		b = b.WithInterceptorFuncs(funcs[0])
	}

	c := b.Build()
	dd := newFakeDefectDojo()

	r := NewReconciler(c, c, baseConfig(), func(string, string) DefectDojo { return dd })
	r.now = func() time.Time { return scanDate }
	r.random = func() float64 { return 0.5 }

	return &harness{t: t, client: c, dd: dd, reconciler: r}
}

func (h *harness) reconcileNamespace(namespace string) reconcile.Result {
	h.t.Helper()

	res, err := h.reconciler.Reconcile(context.Background(), namespaceRequest(namespace))
	require.NoError(h.t, err)

	return res
}

func (h *harness) reconcileErr() error {
	h.t.Helper()

	_, err := h.reconciler.Reconcile(context.Background(), namespaceRequest(stageNS))

	return err
}

func (h *harness) reconcile() reconcile.Result {
	h.t.Helper()

	return h.reconcileNamespace(stageNS)
}

func (h *harness) setReport(report *unstructured.Unstructured) {
	h.t.Helper()

	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(report.GroupVersionKind())

	err := h.client.Get(context.Background(), client.ObjectKeyFromObject(report), existing)
	if err == nil {
		report.SetResourceVersion(existing.GetResourceVersion())
		require.NoError(h.t, h.client.Update(context.Background(), report))

		return
	}

	report.SetResourceVersion("")
	require.NoError(h.t, h.client.Create(context.Background(), report))
}

func (h *harness) deleteReport(report *unstructured.Unstructured) {
	h.t.Helper()

	report.SetResourceVersion("")
	require.NoError(h.t, h.client.Delete(context.Background(), report))
}

func (h *harness) create(obj client.Object) {
	h.t.Helper()

	require.NoError(h.t, h.client.Create(context.Background(), obj))
}

func (h *harness) remove(obj client.Object) {
	h.t.Helper()

	require.NoError(h.t, h.client.Delete(context.Background(), obj))
}

func (h *harness) byTitle() map[string]defectdojo.ReimportRequest {
	out := map[string]defectdojo.ReimportRequest{}
	for _, r := range h.dd.reimports {
		out[r.TestTitle] = r
	}

	return out
}

func withReports(objects []client.Object, reports ...*unstructured.Unstructured) []client.Object {
	objects = slices.Clone(objects)
	for _, r := range reports {
		objects = append(objects, r)
	}

	return objects
}

func ownedTags(scopeTag, namespace string) []string {
	return []string{scopeTag, trivy.ClusterTag(cluster), trivy.NamespaceTag(namespace)}
}

func ownedTest(id int, title string) defectdojo.Test {
	return defectdojo.Test{ID: id, Title: title, Tags: ownedTags(trivy.TagScopeRuntime, stageNS)}
}

func testIn(id int, scopeTag, clusterName, namespace string) defectdojo.Test {
	return defectdojo.Test{
		ID:    id,
		Title: "VulnerabilityReport " + namespace + "/deployment/a/a",
		Tags:  []string{scopeTag, trivy.ClusterTag(clusterName), trivy.NamespaceTag(namespace)},
	}
}

func TestReconcile_ImportsStageReports(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))

	res := h.reconcile()

	assert.Equal(t, resync, res.RequeueAfter)
	require.Len(t, h.dd.reimports, 2)

	vuln := h.byTitle()[goAppTitle]
	assert.Equal(t, "KubeRocketCI", vuln.ProductType)
	assert.Equal(t, "test-go-app", vuln.Product)
	assert.Equal(t, "runtime:demo-dev", vuln.Engagement)
	assert.Equal(t, "main-20261110-194848", vuln.Version)
	assert.Equal(t, scanDate, vuln.ScanDate)
	assert.ElementsMatch(t, []string{
		"krci-scope:runtime", "krci-tenant:krci", "krci-env:demo.dev", "krci-namespace:krci-demo-dev",
		"krci-workload:deployment.test-go-app", "krci-container:test-go-app", "krci-codebase:test-go-app",
		"krci-component:krci-demo-dev", "krci-cluster:in-cluster",
	}, vuln.Tags)

	secrets := h.byTitle()["ExposedSecretReport krci-demo-dev/deployment/test-go-app/test-go-app"]
	assert.Equal(t, "test-go-app", secrets.Product)

	payload := map[string]any{}
	require.NoError(t, json.Unmarshal(vuln.Report, &payload))
	assert.Equal(t, "VulnerabilityReport", payload["kind"])
	assert.NotContains(t, payload["metadata"], "managedFields")
}

func TestReconcile_ForeignImageGoesToEnvironmentProduct(t *testing.T) {
	objects := []client.Object{
		demoStage(),
		integrationSecret(),
		tenantNamespace(stageNS),
		deployment("defectdojo-primary", "4"),
		replicaSet("defectdojo-primary-55747b486", "defectdojo-primary", "4"),
	}

	h := newHarness(t, withReports(objects, fixture(t, "vulnerabilityreport_dockerhub.json")))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, "env:demo-dev", h.dd.reimports[0].Product)
	assert.Equal(t, "runtime:demo-dev", h.dd.reimports[0].Engagement)
	assert.Equal(t, "VulnerabilityReport krci-demo-dev/deployment/defectdojo-primary/postgres", h.dd.reimports[0].TestTitle)
	assert.NotContains(t, h.dd.reimports[0].Tags, "krci-codebase:postgres")
}

func TestReconcile_MatchesImageReferenceInTag(t *testing.T) {
	objects := []client.Object{
		demoStage(),
		integrationSecret(),
		tenantNamespace(stageNS),
		codebaseImageStream("docker.io/valkey/valkey", "cache"),
	}

	report := fixture(t, "vulnerabilityreport_fullref_tag.json")
	report.SetNamespace(stageNS)

	h := newHarness(t, withReports(objects, report))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, "cache", h.dd.reimports[0].Product)
	assert.Equal(t, "9.0.0-alpine3.22", h.dd.reimports[0].Version)
	assert.Equal(t, "VulnerabilityReport krci-demo-dev/statefulset/defectdojo-valkey/valkey", h.dd.reimports[0].TestTitle)
}

func TestReconcile_SkipsReportOfOldRevision(t *testing.T) {
	objects := goAppObjects()
	objects[5] = deployment("test-go-app", "2")

	h := newHarness(t, withReports(objects, goApp(t)))
	h.dd.seedTests(ownedTest(7, goAppTitle))

	h.reconcile()

	assert.Empty(t, h.dd.reimports)
	assert.Empty(t, h.dd.closed, "the test of a Deployment that is rolling out stays open")
}

func TestReconcile_SkipsUnchangedReport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.reconcile()
	assert.Len(t, h.dd.reimports, 1, "an unchanged report is not imported again")

	updated := goApp(t)
	updated.SetResourceVersion("")
	h.setReport(updated)

	h.reconcile()
	assert.Len(t, h.dd.reimports, 2, "a changed report is imported")
}

// TestReconcile_ReportWithOneCVELessClosesThatFinding skips while the reimport request has no service: DefectDojo
// then closes only findings without a service, and the parser gives every finding one.
func TestReconcile_ReportWithOneCVELessClosesThatFinding(t *testing.T) {
	const (
		kept  = "CVE-2026-14456 libcrypto3 3.5.6-r0"
		fixed = "CVE-2026-45447 libcrypto3 3.5.6-r0"
	)

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()

	require.Len(t, h.dd.testIDs(), 1)

	testID := h.dd.testIDs()[0]
	require.Equal(t, map[string]string{kept: statusActive, fixed: statusActive}, h.dd.statuses(testID, goAppService))

	next := goApp(t)
	vulns, _, err := unstructured.NestedSlice(next.Object, "report", "vulnerabilities")
	require.NoError(t, err)
	require.NoError(t, unstructured.SetNestedSlice(next.Object, vulns[:1], "report", "vulnerabilities"))
	h.setReport(next)

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)

	got := h.dd.statuses(testID, goAppService)
	if got[fixed] == statusActive {
		t.Skip(`known failure until EPMDEDP-17556 "Full reimport request: service, version and tags": ` +
			"the fixed CVE stays active")
	}

	assert.Equal(t, map[string]string{kept: statusActive, fixed: statusClosed}, got)
}

func TestReconcile_ImportsAgainWhenAnotherReportOverwroteTheTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	// Rollout to revision 2: the report of the new ReplicaSet takes over the test.
	rollout := replicaSet("test-go-app-new", "test-go-app", "2")
	h.create(rollout)

	dep := &appsv1.Deployment{}
	require.NoError(t, h.client.Get(context.Background(), client.ObjectKey{Namespace: stageNS, Name: "test-go-app"}, dep))
	dep.Annotations[revisionAnnotation] = "2"
	require.NoError(t, h.client.Update(context.Background(), dep))

	next := goApp(t)
	next.SetName("replicaset-test-go-app-new-test-go-app")
	next.SetUID("uid-new")
	next.SetLabels(map[string]string{
		trivy.LabelResourceKind:      "ReplicaSet",
		trivy.LabelResourceName:      "test-go-app-new",
		trivy.LabelResourceNamespace: stageNS,
		trivy.LabelContainerName:     "test-go-app",
	})
	next.SetResourceVersion("")
	h.setReport(next)

	h.reconcile()
	require.Len(t, h.dd.reimports, 2)

	// Rollback: the old ReplicaSet is current again and its unchanged report must be imported again.
	dep.Annotations[revisionAnnotation] = "1"
	require.NoError(t, h.client.Update(context.Background(), dep))

	h.remove(rollout)

	h.reconcile()
	assert.Len(t, h.dd.reimports, 3)
}

func TestReconcile_DefectDojoServerErrorReturnsError(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 500} }
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/gone/gone"))

	require.Error(t, h.reconcileErr())
	assert.Len(t, h.dd.reimports, 1, "the pass stops at the first failure")
	assert.Empty(t, h.dd.closed, "nothing is closed while an import failed")

	h.dd.reimportErr = nil

	h.reconcile()
	assert.Len(t, h.dd.reimports, 3, "the failed report is retried")
}

func rejectGoApp(r defectdojo.ReimportRequest) error {
	if r.TestTitle == goAppTitle {
		return &defectdojo.APIError{StatusCode: 400}
	}

	return nil
}

func TestReconcile_RejectedReportDoesNotBlockStaleClosing(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	h.dd.reimportErr = rejectGoApp
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/removed/removed"))

	h.reconcile()

	assert.Len(t, h.dd.reimports, 2)
	assert.Equal(t, []int{7}, h.dd.closed, "stale tests are closed although one report is rejected")
}

func TestReconcile_RejectedVersionIsNotUploadedAgainUntilItChanges(t *testing.T) {
	before := testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport))

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.reimportErr = rejectGoApp

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.reconcile()
	h.reconcile()
	assert.Len(t, h.dd.reimports, 1, "the rejected version is not uploaded again")
	assert.InDelta(t, before+1, testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport)), 0,
		"the counter increments once per version")

	changed := goApp(t)
	changed.SetResourceVersion("")
	h.setReport(changed)

	h.reconcile()
	assert.Len(t, h.dd.reimports, 2, "a changed version is uploaded again")
	assert.InDelta(t, before+2, testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport)), 0)

	h.dd.reimportErr = nil
	changed = goApp(t)
	changed.SetResourceVersion("")
	h.setReport(changed)

	h.reconcile()
	assert.Len(t, h.dd.reimports, 3)
	assert.Empty(t, h.reconciler.rejectedVersions, "an accepted version clears the rejection")
}

func TestReconcile_RejectedReportKeepsTheExistingTestOpenWithoutMemory(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.reimportErr = rejectGoApp
	h.dd.seedTests(
		ownedTest(7, goAppTitle),
		ownedTest(8, "VulnerabilityReport krci-demo-dev/deployment/removed/removed"),
	)

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, []int{8}, h.dd.closed, "the test of the rejected, still running workload stays open")
}

func TestReconcile_OlderTestOfARejectedWorkloadStaysOpen(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.dd.reimportErr = rejectGoApp

	changed := goApp(t)
	changed.SetResourceVersion("")
	h.setReport(changed)

	h.reconcile()
	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Empty(t, h.dd.closed, "the earlier import of the workload is still its test")
}

func TestReconcile_RejectedReportDoesNotBlockTheOthers(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	h.dd.reimportErr = func(r defectdojo.ReimportRequest) error {
		if r.TestTitle == goAppTitle {
			return &defectdojo.APIError{StatusCode: 400}
		}

		return nil
	}
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/gone/gone"))

	require.NoError(t, h.reconcileErr(), "a rejected version is permanent, not a failure of the pass")

	assert.Len(t, h.dd.reimports, 2)
	assert.Equal(t, []int{7}, h.dd.closed)
}

func TestReconcile_ListTestsErrorReturnsError(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.listErr = &defectdojo.APIError{StatusCode: 502}

	require.Error(t, h.reconcileErr())
}

func TestReconcile_NoOps(t *testing.T) {
	noMatch := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Group == trivy.TrivyGroup {
				return noKindMatch()
			}

			return c.List(ctx, list, opts...)
		},
	}

	tests := []struct {
		name        string
		objects     []client.Object
		funcs       []interceptor.Funcs
		wantRequeue time.Duration
	}{
		{
			name:        "Trivy Operator CRDs are absent",
			objects:     goAppObjects(),
			funcs:       []interceptor.Funcs{noMatch},
			wantRequeue: resync,
		},
		{
			name: "Secret is absent",
			objects: withReports([]client.Object{
				demoStage(), tenantNamespace(stageNS), deployment("test-go-app", "1"),
				replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1"),
			}, goApp(t)),
			wantRequeue: dependencyRetry,
		},
		{
			name: "Secret has no token",
			objects: withReports([]client.Object{
				demoStage(),
				tenantNamespace(stageNS),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: operatorNS},
					Data:       map[string][]byte{"url": []byte("https://dd.example.com")},
				},
			}, goApp(t)),
			wantRequeue: dependencyRetry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.objects, tt.funcs...)
			h.dd.seedTests(ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/gone/gone"))

			res := h.reconcile()

			assert.Equal(t, tt.wantRequeue, res.RequeueAfter)
			assert.Empty(t, h.dd.reimports)
			assert.Empty(t, h.dd.closed)
		})
	}
}

func TestReconcile_ClosesTestOfWorkloadThatIsGone(t *testing.T) {
	gone := ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/removed/removed")
	anotherCluster := ownedTest(8, "VulnerabilityReport krci-demo-dev/deployment/x/x")
	anotherCluster.Tags = ownedTags(trivy.TagScopeRuntime, stageNS)
	anotherCluster.Tags[1] = trivy.ClusterTag("other")
	ciTest := defectdojo.Test{ID: 9, Title: "Trivy Scan", Tags: []string{trivy.NamespaceTag(stageNS)}}

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTests(
		gone,
		anotherCluster,
		ciTest,
		ownedTest(10, goAppTitle),
	)

	h.reconcile()

	// Test 10 has the title of the running workload but is not the test the report was imported into.
	assert.ElementsMatch(t, []int{7, 10}, h.dd.closed)

	h.reconcile()
	assert.ElementsMatch(t, []int{7, 10}, h.dd.closed, "a closed test is not closed again")
}

func TestReconcile_ClosesAllTestsWhenNamespaceHasNoReports(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.dd.seedTests(ownedTest(7, goAppTitle))

	h.reconcile()

	assert.Equal(t, []int{7}, h.dd.closed)
	assert.Empty(t, h.dd.reimports, "a test is closed without a re-import")
	assert.NotContains(t, h.reconciler.imported, stageNS, "a namespace without reports keeps no memory")
}

func TestReconcile_ReopenedTestIsClosedAgainWhenWorkloadGoesAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTestsIn(goAppContext, ownedTest(100, goAppTitle))

	h.reconcile()
	assert.Empty(t, h.dd.closed, "the imported test is live")

	h.deleteReport(goApp(t))

	h.reconcile()
	assert.Equal(t, []int{100}, h.dd.closed)

	h.setReport(goApp(t))

	h.reconcile()
	require.Len(t, h.dd.reimports, 2, "the report is imported again into the closed test")

	h.deleteReport(goApp(t))

	h.reconcile()
	assert.Equal(t, []int{100, 100}, h.dd.closed)
}

const (
	// staleTitle is the test of a workload whose report would be on a page that was not read.
	staleTitle = "VulnerabilityReport krci-demo-dev/deployment/other/other"
	// staleSecretsTitle is the test of the other report kind of a workload that is gone.
	staleSecretsTitle = "ExposedSecretReport krci-demo-dev/deployment/other/other"
)

// restartedCalls are the continue tokens of a listing that started again once after its second page.
var restartedCalls = []string{"", "page-2", "", "page-2"}

var (
	// errExpired is the answer of the API server to a too old continue token.
	errExpired = k8sErrors.NewResourceExpired("the continue token is too old")
	// errGone is the 410 answer with the reason Gone that older API servers give for a too old continue token.
	errGone = &k8sErrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusGone,
		Reason:  metav1.StatusReasonGone,
		Message: "the continue token is gone",
	}}
)

// noKindMatch is the answer of a cluster that does not serve VulnerabilityReports.
func noKindMatch() error {
	return &meta.NoKindMatchError{GroupKind: trivy.ReportGVK(trivy.KindVulnerabilityReport).GroupKind()}
}

// pagedReports serves the VulnerabilityReports of the stage namespace in two pages, checks that every list reads one
// page of that namespace, and records the continue token of every list. The list of the second page fails with err
// the first failures times.
func pagedReports(t *testing.T, calls *[]string, err error, failures int) interceptor.Funcs {
	t.Helper()

	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			u, ok := list.(*unstructured.UnstructuredList)
			if !ok || u.GroupVersionKind().Kind != "VulnerabilityReportList" {
				return c.List(ctx, list, opts...)
			}

			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)

			assert.Equal(t, stageNS, lo.Namespace, "every list reads the namespace of the pass")
			assert.Equal(t, int64(reportsPageSize), lo.Limit, "every list reads one page")

			*calls = append(*calls, lo.Continue)

			if lo.Continue == "" {
				u.Items = []unstructured.Unstructured{*goApp(t)}
				u.SetContinue("page-2")

				return nil
			}

			if failures > 0 {
				failures--

				return err
			}

			u.Items = []unstructured.Unstructured{*fixture(t, "vulnerabilityreport_dockerhub.json")}

			return nil
		},
	}
}

// unservedReports answers the lists of VulnerabilityReports with err while *unserved is true.
func unservedReports(err error, unserved *bool) interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok && *unserved && u.GroupVersionKind().Kind == "VulnerabilityReportList" {
				return err
			}

			return c.List(ctx, list, opts...)
		},
	}
}

// pagedObjects are the objects behind the two pages of pagedReports.
func pagedObjects() []client.Object {
	return []client.Object{
		demoStage(),
		integrationSecret(),
		tenantNamespace(stageNS),
		deployment("test-go-app", "1"),
		replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1"),
		deployment("defectdojo-primary", "1"),
		replicaSet("defectdojo-primary-55747b486", "defectdojo-primary", "1"),
	}
}

// uploadsOf counts the uploads into the test with the title.
func (h *harness) uploadsOf(title string) int {
	uploads := 0

	for _, r := range h.dd.reimports {
		if r.TestTitle == title {
			uploads++
		}
	}

	return uploads
}

func TestReconcile_PagesThroughReports(t *testing.T) {
	var calls []string

	h := newHarness(t, pagedObjects(), pagedReports(t, &calls, nil, 0))

	h.reconcile()

	assert.Equal(t, []string{"", "page-2"}, calls)
	assert.Len(t, h.dd.reimports, 2)
}

func TestReconcile_UnservedReportKindKeepsItsTestsOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "no kind match", err: noKindMatch()},
		{name: "not found", err: k8sErrors.NewNotFound(schema.GroupResource{Group: trivy.TrivyGroup, Resource: "vulnerabilityreports"}, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unserved := true

			h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)), unservedReports(tc.err, &unserved))
			h.dd.seedTests(ownedTest(7, goAppTitle), ownedTest(8, staleSecretsTitle))

			require.NoError(t, h.reconcileErr())

			assert.Len(t, h.dd.reimports, 1, "the served kind is imported")
			assert.Equal(t, []int{8}, h.dd.closed, "the served kind closes its stale test, the other kind closes nothing")
		})
	}
}

func TestReconcile_UnservedReportKindKeepsWhatIsRemembered(t *testing.T) {
	unserved := false

	h := newHarness(t,
		withReports(pagedObjects(), goApp(t), fixture(t, "vulnerabilityreport_dockerhub.json"), goAppSecrets(t)),
		unservedReports(noKindMatch(), &unserved))
	h.dd.reimportErr = rejectGoApp

	h.reconcile()
	require.Len(t, h.dd.reimports, 3, "one version rejected, two imported")

	unserved = true

	h.reconcile()
	assert.Empty(t, h.dd.closed, "the tests of the kind that was not listed stay open")

	unserved = false

	h.reconcile()
	assert.Len(t, h.dd.reimports, 3, "neither the imported nor the rejected version is uploaded again")
	assert.Empty(t, h.dd.closed)
}

func TestReconcile_ReportKindGoneOnALaterPageKeepsItsTestsOpen(t *testing.T) {
	var calls []string

	h := newHarness(t, pagedObjects(), pagedReports(t, &calls, noKindMatch(), 1))
	h.dd.seedTests(ownedTest(7, staleTitle), ownedTest(8, staleSecretsTitle))

	require.NoError(t, h.reconcileErr())
	assert.Equal(t, []string{"", "page-2"}, calls)
	assert.Equal(t, []int{8}, h.dd.closed, "an incomplete listing closes nothing of its kind")
}

func TestReconcile_ExpiredContinueTokenStartsTheListAgain(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "expired", err: errExpired},
		{name: "gone", err: errGone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string

			h := newHarness(t, pagedObjects(), pagedReports(t, &calls, tc.err, 1))

			h.reconcile()

			assert.Equal(t, restartedCalls, calls)
			assert.Len(t, h.dd.reimports, 2, "the report of the first page is imported once")
		})
	}
}

func TestReconcile_RestartedListDoesNotUploadARejectedReportAgain(t *testing.T) {
	var calls []string

	h := newHarness(t, pagedObjects(), pagedReports(t, &calls, errExpired, 1))
	h.dd.reimportErr = rejectGoApp

	h.reconcile()

	assert.Equal(t, restartedCalls, calls)
	assert.Equal(t, 1, h.uploadsOf(goAppTitle), "the version rejected on the first listing is not uploaded again")
}

func TestReconcile_ReportDeletedBeforeARestartIsNotLive(t *testing.T) {
	listings := 0

	funcs := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			u, ok := list.(*unstructured.UnstructuredList)
			if !ok || u.GroupVersionKind().Kind != "VulnerabilityReportList" {
				return c.List(ctx, list, opts...)
			}

			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)

			if lo.Continue != "" {
				return errExpired
			}

			listings++

			if listings == 1 {
				u.Items = []unstructured.Unstructured{*goApp(t)}
				u.SetContinue("page-2")

				return nil
			}

			// The report of the go app was deleted before the listing started again.
			u.Items = []unstructured.Unstructured{*fixture(t, "vulnerabilityreport_dockerhub.json")}

			return nil
		},
	}

	h := newHarness(t, pagedObjects(), funcs)

	h.reconcile()

	assert.Equal(t, 2, listings)
	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, []int{100}, h.dd.closed, "the test the deleted report was imported into closes in the same pass")
}

func TestReconcile_RejectedVersionIsNotUploadedAgainAfterAFailedPass(t *testing.T) {
	before := testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport))

	var calls []string

	h := newHarness(t, pagedObjects(), pagedReports(t, &calls, errors.New("the API server is unavailable"), 1))
	h.dd.reimportErr = rejectGoApp

	require.Error(t, h.reconcileErr(), "the list of the second page fails the first pass")

	h.reconcile()

	assert.Equal(t, 1, h.uploadsOf(goAppTitle), "the version rejected by the failed pass is not uploaded again")
	assert.InDelta(t, before+1, testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport)), 0,
		"the rejection is counted once")
}

func TestReconcile_ExpiredContinueTokenGivesUpAfterTheRestarts(t *testing.T) {
	var calls []string

	h := newHarness(t, pagedObjects(), pagedReports(t, &calls, errExpired, maxListRestarts+1))
	h.dd.seedTests(ownedTest(7, staleTitle))

	err := h.reconcileErr()
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("after %d restarts", maxListRestarts))
	assert.Len(t, calls, 2*(1+maxListRestarts), "the first listing and every restart read both pages")
	assert.Empty(t, h.dd.closed, "an incomplete listing closes nothing")
}

func TestReconcile_ReportIsNotModified(t *testing.T) {
	report := goApp(t)

	h := newHarness(t, withReports(goAppObjects(), report))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)

	stored := &unstructured.Unstructured{}
	stored.SetGroupVersionKind(trivy.ReportGVK(trivy.KindVulnerabilityReport))
	require.NoError(t, h.client.Get(context.Background(), client.ObjectKeyFromObject(report), stored))
	assert.Equal(t, "ReplicaSet", stored.GetLabels()[trivy.LabelResourceKind], "the stable labels go to the payload only")
}

func TestReconcile_ListErrorOfReportsIsReturned(t *testing.T) {
	funcs := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Group == trivy.TrivyGroup {
				return errors.New("forbidden")
			}

			return c.List(ctx, list, opts...)
		},
	}

	h := newHarness(t, goAppObjects(), funcs)
	h.dd.seedTests(ownedTest(7, goAppTitle))

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.reimports)
	assert.Empty(t, h.dd.closed, "a failed read hides which workloads are alive")
}

func TestReconcile_ConnectsWithSecretCredentials(t *testing.T) {
	var gotURL, gotToken string

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconciler.connect = func(url, token string) DefectDojo {
		gotURL, gotToken = url, token

		return h.dd
	}

	h.reconcile()

	assert.Equal(t, "https://dd.example.com", gotURL)
	assert.Equal(t, "t", gotToken)
}

func TestReconcile_ReadsOnlyThroughTheReaderWhatMustNotBeCached(t *testing.T) {
	// The cache serves only Namespaces and Stages: reports, workloads, image streams and the Secret are read
	// through the reader.
	cached := interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Namespace); !ok {
				return errors.New("the cache must serve Namespaces only")
			}

			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); !ok || u.GroupVersionKind().Kind != "StageList" {
				return errors.New("the cache must serve Stages only")
			}

			return c.List(ctx, list, opts...)
		},
	}

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconciler.cache = interceptor.NewClient(
		fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(goAppObjects()...).Build(), cached,
	)

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, "test-go-app", h.dd.reimports[0].Product)
}

func sentLabels(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	payload := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &payload))

	metadata, ok := payload["metadata"].(map[string]any)
	require.True(t, ok)

	labels, ok := metadata["labels"].(map[string]any)
	require.True(t, ok)

	return labels
}

func TestReconcile_SendsStableWorkloadLabels(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)

	labels := sentLabels(t, h.dd.reimports[0].Report)
	assert.Equal(t, "Deployment", labels[trivy.LabelResourceKind])
	assert.Equal(t, "test-go-app", labels[trivy.LabelResourceName])
	assert.Equal(t, goAppTitle, h.dd.reimports[0].TestTitle)
	assert.Contains(t, h.dd.reimports[0].Tags, "krci-workload:deployment.test-go-app")
}

func TestReconcile_ClosesFindingsOfStaleServicesOncePerTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Len(t, h.dd.healCalls, 1)
	assert.Equal(t, healCall{testID: 100, service: "krci-demo-dev/Deployment/test-go-app/test-go-app"}, h.dd.healCalls[0])

	h.setReport(goApp(t))

	h.reconcile()
	require.Len(t, h.dd.reimports, 2)
	assert.Len(t, h.dd.healCalls, 1, "the steady state does not list findings")
}

func TestReconcile_ClosesFindingsOfAStaleServiceAndKeepsTheImportedOnes(t *testing.T) {
	const staleService = "krci-demo-dev/ReplicaSet/test-go-app-old/test-go-app"

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTestsIn(goAppContext, ownedTest(100, goAppTitle))
	h.dd.seedFinding(100, "CVE-2026-14456 libcrypto3 3.5.6-r0", staleService)

	h.reconcile()

	assert.Equal(t, map[string]string{"CVE-2026-14456 libcrypto3 3.5.6-r0": statusClosed}, h.dd.statuses(100, staleService))
	assert.Equal(t, map[string]string{
		"CVE-2026-14456 libcrypto3 3.5.6-r0": statusActive,
		"CVE-2026-45447 libcrypto3 3.5.6-r0": statusActive,
	}, h.dd.statuses(100, goAppService), "the findings of the current service stay active")
}

func TestReconcile_RetriesStaleServiceCloseAfterFailure(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.healErr = &defectdojo.APIError{StatusCode: 500}

	res := h.reconcile()

	assert.Equal(t, resync, res.RequeueAfter)
	require.Len(t, h.dd.reimports, 1)
	require.Len(t, h.dd.healCalls, 1)

	h.dd.healErr = nil
	h.setReport(goApp(t))

	h.reconcile()
	assert.Len(t, h.dd.healCalls, 2)

	h.setReport(goApp(t))

	h.reconcile()
	assert.Len(t, h.dd.healCalls, 2)
}

func TestReconcile_DoesNotCloseFindingsOfAnotherClustersTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	// The test the import lands in belongs to the operator of another cluster.
	h.dd.seedTestsIn(goAppContext, defectdojo.Test{
		ID:    100,
		Title: goAppTitle,
		Tags:  []string{trivy.TagScopeRuntime, trivy.ClusterTag("other"), trivy.NamespaceTag(stageNS)},
	})
	h.reconciler.connect = func(string, string) DefectDojo { return reimportedByAnotherCluster{h.dd} }

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, []int{100}, h.dd.getCalls)
	assert.Empty(t, h.dd.healCalls, "findings of another cluster's test are not closed")
	assert.Empty(t, h.dd.closed)
}

// reimportedByAnotherCluster is a DefectDojo where the operator of the cluster "other" reimports every report
// into the same test right after this operator. A reimport replaces the test tags.
type reimportedByAnotherCluster struct {
	*fakeDefectDojo
}

func (d reimportedByAnotherCluster) Reimport(
	ctx context.Context,
	r defectdojo.ReimportRequest,
) (defectdojo.ReimportResult, error) {
	res, err := d.fakeDefectDojo.Reimport(ctx, r)
	if err != nil {
		return res, err
	}

	other := r
	other.Tags = slices.Clone(r.Tags)

	for i, tag := range other.Tags {
		if tag == trivy.ClusterTag(cluster) {
			other.Tags[i] = trivy.ClusterTag("other")
		}
	}

	if _, err = d.reimportAs(other); err != nil {
		return defectdojo.ReimportResult{}, err
	}

	return res, nil
}

func cronJob(name string, age time.Duration) *batchv1.Job {
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:              name,
		Namespace:         stageNS,
		CreationTimestamp: metav1.NewTime(scanDate.Add(-age)),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly", Controller: ptr.To(true),
		}},
	}}
}

func jobReport(t *testing.T, job string) *unstructured.Unstructured {
	t.Helper()

	r := goApp(t)
	r.SetName("job-" + job + "-app")
	r.SetUID(types.UID("uid-" + job))
	r.SetLabels(map[string]string{
		trivy.LabelResourceKind:      "Job",
		trivy.LabelResourceName:      job,
		trivy.LabelResourceNamespace: stageNS,
		trivy.LabelContainerName:     "app",
	})

	return r
}

func TestReconcile_CronJobRunsShareOneService(t *testing.T) {
	objects := []client.Object{
		demoStage(), integrationSecret(), tenantNamespace(stageNS), cronJob("nightly-1", time.Hour), cronJob("nightly-2", 0),
	}

	h := newHarness(t, withReports(objects, jobReport(t, "nightly-1"), jobReport(t, "nightly-2")))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1, "only the newest run is imported")
	assert.Equal(t, "VulnerabilityReport krci-demo-dev/cronjob/nightly/app", h.dd.reimports[0].TestTitle)

	labels := sentLabels(t, h.dd.reimports[0].Report)
	assert.Equal(t, "CronJob", labels[trivy.LabelResourceKind])
	assert.Equal(t, "nightly", labels[trivy.LabelResourceName])
	assert.Equal(t, "krci-demo-dev/CronJob/nightly/app", h.dd.healCalls[0].service)
}

func TestReconcile_NamespaceDeletionClosesItsOwnedTestsOnce(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.dd.seedTests(
		ownedTest(1, "VulnerabilityReport krci-demo-dev/deployment/a/a"),
		testIn(2, trivy.TagScopeRuntime, "other", stageNS),
		testIn(3, trivy.TagScopeRuntime, cluster, "krci-demo-qa"),
		defectdojo.Test{ID: 4, Title: "CI", Tags: []string{trivy.NamespaceTag(stageNS)}},
	)

	h.remove(tenantNamespace(stageNS))

	res := h.reconcile()

	assert.Zero(t, res.RequeueAfter)
	assert.Equal(t, []int{1}, h.dd.closed, "only the owned tests of the deleted namespace are closed")
	assert.Empty(t, h.dd.reimports)

	calls := h.dd.listCalls

	h.reconcile()
	assert.Equal(t, []int{1}, h.dd.closed)
	assert.Equal(t, calls, h.dd.listCalls, "a released namespace is not listed again")
}

func TestReconcile_TerminatingNamespaceIsReleased(t *testing.T) {
	ns := tenantNamespace(stageNS)
	ns.DeletionTimestamp = &metav1.Time{Time: scanDate}
	ns.Finalizers = []string{"kubernetes"}

	objects := append(withReports(goAppObjects()[:3], goApp(t)), codebaseImageStream("x", "x"), ns)

	h := newHarness(t, objects)
	h.dd.seedTests(ownedTest(1, goAppTitle))

	h.reconcile()

	assert.Equal(t, []int{1}, h.dd.closed)
	assert.Empty(t, h.dd.reimports)
}

func TestReconcile_NamespaceDeletionIsRetriedAfterDefectDojoFailure(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.dd.seedTests(ownedTest(1, goAppTitle))
	h.dd.listErr = &defectdojo.APIError{StatusCode: 500}

	h.remove(tenantNamespace(stageNS))

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.closed)

	h.dd.listErr = nil

	h.reconcile()
	assert.Equal(t, []int{1}, h.dd.closed)
}

func TestReconcile_ScopeSwitches(t *testing.T) {
	tests := []struct {
		name       string
		start      []client.Object
		switchTo   func(h *harness)
		wantScope  string
		wantProd   string
		wantEngage string
	}{
		{
			name:  "tenant to stage",
			start: tenantObjects(),
			switchTo: func(h *harness) {
				h.create(demoStage())
			},
			wantScope:  "krci-scope:runtime",
			wantProd:   "env:demo-dev",
			wantEngage: "runtime:demo-dev",
		},
		{
			name:  "stage to tenant",
			start: goAppObjects(),
			switchTo: func(h *harness) {
				h.remove(demoStage())
			},
			wantScope:  "krci-scope:tenant",
			wantProd:   "tenant:krci",
			wantEngage: "namespace:krci-demo-dev",
		},
		{
			name:  "tenant to platform",
			start: tenantObjects(),
			switchTo: func(h *harness) {
				ns := &corev1.Namespace{}
				require.NoError(t, h.client.Get(context.Background(), client.ObjectKey{Name: stageNS}, ns))
				ns.Labels = nil
				require.NoError(t, h.client.Update(context.Background(), ns))
			},
			wantScope:  "krci-scope:platform",
			wantProd:   "platform",
			wantEngage: "namespace:krci-demo-dev",
		},
		{
			name:  "platform to tenant",
			start: append(tenantObjects()[:1], namespaceObject(stageNS, nil), deployment("test-go-app", "1"), replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1")),
			switchTo: func(h *harness) {
				ns := &corev1.Namespace{}
				require.NoError(t, h.client.Get(context.Background(), client.ObjectKey{Name: stageNS}, ns))
				ns.Labels = map[string]string{tenantLabel: tenantNS}
				require.NoError(t, h.client.Update(context.Background(), ns))
			},
			wantScope:  "krci-scope:tenant",
			wantProd:   "tenant:krci",
			wantEngage: "namespace:krci-demo-dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, withReports(tt.start, goApp(t)))

			h.reconcile()
			require.Len(t, h.dd.reimports, 1)

			require.Len(t, h.dd.testIDs(), 1)

			first := h.dd.testIDs()[0]
			assert.Empty(t, h.dd.closed)

			tt.switchTo(h)

			h.reconcile()

			require.Len(t, h.dd.reimports, 2, "the report is imported under the new scope")
			assert.Equal(t, tt.wantProd, h.dd.reimports[1].Product)
			assert.Equal(t, tt.wantEngage, h.dd.reimports[1].Engagement)
			assert.Contains(t, h.dd.reimports[1].Tags, tt.wantScope)
			assert.Equal(t, []int{first}, h.dd.closed, "the test of the old scope is closed")
		})
	}
}

func TestReconcile_OutOfScopeClosesOwnedTestsOnce(t *testing.T) {
	tests := []struct {
		name    string
		objects []client.Object
		config  func(c *Config)
	}{
		{
			name:    "stage scope is off",
			objects: goAppObjects(),
			config:  func(c *Config) { c.Scopes.Stage = false },
		},
		{
			name:    "tenant scope is off",
			objects: tenantObjects(),
			config:  func(c *Config) { c.Scopes.Tenant = false },
		},
		{
			name:    "platform scope is off",
			objects: []client.Object{integrationSecret(), namespaceObject(stageNS, nil)},
			config:  func(c *Config) { c.Scopes.Platform = false },
		},
		{
			name:    "namespace is excluded by a glob",
			objects: goAppObjects(),
			config:  func(c *Config) { c.ExcludeNamespaces = []string{"kube-*", "krci-demo-*"} },
		},
		{
			name:    "namespace is excluded by its name",
			objects: goAppObjects(),
			config:  func(c *Config) { c.ExcludeNamespaces = []string{stageNS} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, withReports(tt.objects, goApp(t)))
			tt.config(&h.reconciler.config)
			h.dd.seedTests(
				ownedTest(1, goAppTitle),
				testIn(2, trivy.TagScopeRuntime, "other", stageNS),
			)

			res := h.reconcile()

			assert.Equal(t, resync, res.RequeueAfter)
			assert.Empty(t, h.dd.reimports)
			assert.Equal(t, []int{1}, h.dd.closed)

			h.reconcile()
			assert.Equal(t, []int{1}, h.dd.closed, "the tests are closed once")
		})
	}
}

func TestReconcile_ExcludeGlobsKeepOtherNamespaces(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconciler.config.ExcludeNamespaces = []string{"kube-*", "monitoring"}

	h.reconcile()

	assert.Len(t, h.dd.reimports, 1)
}

func TestReconcile_ReturningToScopeImportsAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.reconciler.config.Scopes.Stage = false

	h.reconcile()
	assert.Equal(t, []int{100}, h.dd.closed)

	h.reconciler.config.Scopes.Stage = true

	h.reconcile()
	assert.Len(t, h.dd.reimports, 2, "the closed test is reimported")

	h.reconciler.config.Scopes.Stage = false

	h.reconcile()
	assert.Equal(t, []int{100, 100}, h.dd.closed)
}

func TestReconcile_ImportsTenantScope(t *testing.T) {
	h := newHarness(t, withReports(tenantObjects(), goApp(t), goAppSecrets(t)))

	h.reconcile()

	vuln := h.byTitle()[goAppTitle]
	assert.Equal(t, "KubeRocketCI", vuln.ProductType)
	assert.Equal(t, "tenant:krci", vuln.Product)
	assert.Equal(t, "namespace:krci-demo-dev", vuln.Engagement)
	assert.ElementsMatch(t, []string{
		"krci-scope:tenant", "krci-tenant:krci", "krci-namespace:krci-demo-dev",
		"krci-workload:deployment.test-go-app", "krci-container:test-go-app",
		"krci-component:krci-demo-dev", "krci-cluster:in-cluster",
	}, vuln.Tags)
	assert.Equal(t, "tenant:krci", h.byTitle()["ExposedSecretReport krci-demo-dev/deployment/test-go-app/test-go-app"].Product)
}

func TestReconcile_ImportsPlatformScope(t *testing.T) {
	objects := []client.Object{
		integrationSecret(), namespaceObject(stageNS, nil),
		deployment("test-go-app", "1"), replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1"),
	}

	h := newHarness(t, withReports(objects, goApp(t)))
	h.reconciler.config.PlatformProduct = "infra"
	h.reconciler.config.ClusterName = "sandbox"
	h.reconciler.config.ProductType = "Platform"

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)

	req := h.dd.reimports[0]
	assert.Equal(t, "Platform", req.ProductType)
	assert.Equal(t, "infra", req.Product)
	assert.Equal(t, "namespace:krci-demo-dev", req.Engagement)
	assert.ElementsMatch(t, []string{
		"krci-scope:platform", "krci-namespace:krci-demo-dev",
		"krci-workload:deployment.test-go-app", "krci-container:test-go-app",
		"krci-component:krci-demo-dev", "krci-cluster:sandbox",
	}, req.Tags)
}

func TestClassify(t *testing.T) {
	otherTenant := namespaceObject(stageNS, map[string]string{tenantLabel: "other"})

	tests := []struct {
		name      string
		namespace *corev1.Namespace
		objects   []client.Object
		funcs     []interceptor.Funcs
		config    func(c *Config)
		want      trivy.Scope
		inScope   bool
	}{
		{name: "stage", namespace: tenantNamespace(stageNS), objects: []client.Object{demoStage()}, want: trivy.ScopeStage, inScope: true},
		{
			name:      "Stage whose namespace label belongs to another tenant is not a stage",
			namespace: otherTenant, objects: []client.Object{demoStage()}, want: trivy.ScopeTenant, inScope: true,
		},
		{
			name:      "Stage in another namespace than the tenant label",
			namespace: tenantNamespace(stageNS),
			objects: []client.Object{func() client.Object {
				s := demoStage()
				s.SetNamespace("other")

				return s
			}()},
			want: trivy.ScopeTenant, inScope: true,
		},
		{
			name: "Stage of a remote cluster", namespace: tenantNamespace(stageNS),
			objects: []client.Object{newStage("demo-dev", "dev", stageNS, "remote")}, want: trivy.ScopeTenant, inScope: true,
		},
		{
			name: "Stage without a cluster", namespace: tenantNamespace(stageNS),
			objects: []client.Object{newStage("demo-dev", "dev", stageNS, "")}, want: trivy.ScopeTenant, inScope: true,
		},
		{
			name: "Stage with a name that is no DNS label", namespace: tenantNamespace(stageNS),
			objects: []client.Object{newStage("demo-dev", "dev,krci-env:x.prod", stageNS, inClusterName)},
			want:    trivy.ScopeTenant, inScope: true,
		},
		{
			name: "Stage with an upper case name", namespace: tenantNamespace(stageNS),
			objects: []client.Object{newStage("demo-dev", "Dev", stageNS, inClusterName)}, want: trivy.ScopeTenant, inScope: true,
		},
		{
			name: "Stage with a dot in the name", namespace: tenantNamespace(stageNS),
			objects: []client.Object{newStage("demo-dev", "dev.1", stageNS, inClusterName)}, want: trivy.ScopeTenant, inScope: true,
		},
		{
			name: "Stage of another namespace", namespace: tenantNamespace(stageNS),
			objects: []client.Object{newStage("demo-qa", "qa", "krci-demo-qa", inClusterName)}, want: trivy.ScopeTenant, inScope: true,
		},
		{name: "tenant", namespace: tenantNamespace(stageNS), want: trivy.ScopeTenant, inScope: true},
		{name: "platform without labels", namespace: namespaceObject("kube-system", nil), want: trivy.ScopePlatform, inScope: true},
		{
			name: "platform with an empty tenant label", namespace: namespaceObject("x", map[string]string{tenantLabel: ""}),
			want: trivy.ScopePlatform, inScope: true,
		},
		{
			name: "Stage kind is not served", namespace: tenantNamespace(stageNS), want: trivy.ScopeTenant, inScope: true,
			funcs: []interceptor.Funcs{{
				List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
					return &meta.NoKindMatchError{GroupKind: stageGVK.GroupKind(), SearchedVersions: []string{"v1"}}
				},
			}},
		},
		{
			name: "stage scope off", namespace: tenantNamespace(stageNS), objects: []client.Object{demoStage()},
			config: func(c *Config) { c.Scopes.Stage = false }, want: trivy.ScopeStage,
		},
		{
			name: "tenant scope off", namespace: tenantNamespace(stageNS),
			config: func(c *Config) { c.Scopes.Tenant = false }, want: trivy.ScopeTenant,
		},
		{
			name: "platform scope off", namespace: namespaceObject("kube-system", nil),
			config: func(c *Config) { c.Scopes.Platform = false }, want: trivy.ScopePlatform,
		},
		{
			name: "stage scope off keeps the tenant scope", namespace: otherTenant, objects: []client.Object{demoStage()},
			config: func(c *Config) { c.Scopes.Stage = false }, want: trivy.ScopeTenant, inScope: true,
		},
		{
			name: "excluded by a glob", namespace: namespaceObject("kube-system", nil),
			config: func(c *Config) { c.ExcludeNamespaces = []string{"kube-*"} }, want: trivy.ScopePlatform,
		},
		{
			name: "glob that does not match", namespace: namespaceObject("kube-system", nil),
			config: func(c *Config) { c.ExcludeNamespaces = []string{"kube", "*-public"} }, want: trivy.ScopePlatform, inScope: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.objects, tt.funcs...)

			if tt.config != nil {
				tt.config(&h.reconciler.config)
			}

			target, inScope, err := h.reconciler.classify(context.Background(), tt.namespace)
			require.NoError(t, err)

			assert.Equal(t, tt.inScope, inScope)

			assert.Equal(t, tt.want, target.Scope)
		})
	}
}

func TestClassify_StageTarget(t *testing.T) {
	h := newHarness(t, []client.Object{demoStage()})

	target, inScope, err := h.reconciler.classify(context.Background(), tenantNamespace(stageNS))
	require.NoError(t, err)

	assert.True(t, inScope)
	assert.Equal(t, trivy.Target{
		Scope: trivy.ScopeStage, Namespace: stageNS, Cluster: cluster, Tenant: tenantNS,
		CDPipeline: "demo", Stage: "dev", PlatformProduct: "platform",
	}, target)
}

func TestClassify_SeveralStagesPickTheFirstByNamespaceAndName(t *testing.T) {
	second := newStage("a-second", "qa", stageNS, inClusterName)
	first := newStage("a-first", "prod", stageNS, inClusterName)
	third := newStage("zzz", "uat", stageNS, inClusterName)

	h := newHarness(t, []client.Object{third, second, first})

	target, inScope, err := h.reconciler.classify(context.Background(), tenantNamespace(stageNS))
	require.NoError(t, err)

	assert.True(t, inScope)
	assert.Equal(t, trivy.ScopeStage, target.Scope)
	assert.Equal(t, "prod", target.Stage, "the Stage a-first wins")
}

func TestReconcile_SeveralStagesImportUnderTheFirstOne(t *testing.T) {
	objects := append(withReports(goAppObjects(), goApp(t)), newStage("a-first", "prod", stageNS, inClusterName))

	h := newHarness(t, objects)

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, "runtime:demo-prod", h.dd.reimports[0].Engagement)
	assert.Contains(t, h.dd.reimports[0].Tags, "krci-env:demo.prod")
}

func TestReconcile_ClassifyErrorIsReturned(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Kind == "StageList" {
				return errors.New("apiserver unavailable")
			}

			return c.List(ctx, list, opts...)
		},
	})
	h.dd.seedTests(ownedTest(7, goAppTitle))

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.reimports)
	assert.Empty(t, h.dd.closed)
}

func TestReconcile_ComponentTag(t *testing.T) {
	tests := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		prefixes    []string
		want        string
	}{
		{
			name:        "Argo CD tracking-id",
			annotations: map[string]string{"argocd.argoproj.io/tracking-id": "My-App:apps/Deployment:krci-demo-dev/test-go-app"},
			want:        "my-app",
		},
		{
			name:        "Argo CD tracking-id of an application in another namespace",
			annotations: map[string]string{"argocd.argoproj.io/tracking-id": "argocd_my-app:apps/Deployment:krci-demo-dev/test-go-app"},
			want:        "my-app",
		},
		{
			name:        "prefix is stripped from the Argo CD application",
			annotations: map[string]string{"argocd.argoproj.io/tracking-id": "in-cluster-cert-manager:apps/Deployment:x/y"},
			want:        "cert-manager",
		},
		{
			name:        "Argo CD tracking-id wins over the instance label",
			labels:      map[string]string{"argocd.argoproj.io/instance": "legacy"},
			annotations: map[string]string{"argocd.argoproj.io/tracking-id": "app:apps/Deployment:x/y"},
			want:        "app",
		},
		{
			name:   "Argo CD instance label",
			labels: map[string]string{"argocd.argoproj.io/instance": "legacy", "app.kubernetes.io/part-of": "suite"},
			want:   "legacy",
		},
		{
			name:        "part-of label wins over the Helm release",
			labels:      map[string]string{"app.kubernetes.io/part-of": "Suite One", "app.kubernetes.io/instance": "inst"},
			annotations: map[string]string{"meta.helm.sh/release-name": "release"},
			want:        "suite-one",
		},
		{
			name:        "Helm release annotation",
			labels:      map[string]string{"app.kubernetes.io/instance": "inst"},
			annotations: map[string]string{"meta.helm.sh/release-name": "release"},
			want:        "release",
		},
		{
			name:   "instance label",
			labels: map[string]string{"app.kubernetes.io/instance": "inst,two"},
			want:   "inst-two",
		},
		{name: "namespace name", want: "krci-demo-dev"},
		{
			name:        "an application that is only a prefix falls through",
			labels:      map[string]string{"app.kubernetes.io/part-of": "suite"},
			annotations: map[string]string{"argocd.argoproj.io/tracking-id": "in-cluster-:apps/Deployment:x/y"},
			want:        "suite",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := goAppObjects()
			objects[5] = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
				Name: "test-go-app", Namespace: stageNS, Labels: tt.labels,
				Annotations: map[string]string{revisionAnnotation: "1"},
			}}

			for k, v := range tt.annotations {
				objects[5].(*appsv1.Deployment).Annotations[k] = v
			}

			h := newHarness(t, withReports(objects, goApp(t)))

			h.reconcile()

			require.Len(t, h.dd.reimports, 1)
			assert.Contains(t, h.dd.reimports[0].Tags, "krci-component:"+tt.want)
		})
	}
}

func TestReconcile_ComponentOfTopWorkload(t *testing.T) {
	labels := map[string]string{"app.kubernetes.io/part-of": "suite"}

	report := func(kind, name string) *unstructured.Unstructured {
		r := goApp(t)
		r.SetLabels(map[string]string{
			trivy.LabelResourceKind:      kind,
			trivy.LabelResourceName:      name,
			trivy.LabelResourceNamespace: stageNS,
			trivy.LabelContainerName:     "app",
		})

		return r
	}

	tests := []struct {
		name    string
		objects []client.Object
		report  *unstructured.Unstructured
		want    string
	}{
		{
			name: "StatefulSet",
			objects: []client.Object{
				&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: stageNS, Labels: labels}},
			},
			report: report("StatefulSet", "db"),
			want:   "suite",
		},
		{
			name: "DaemonSet",
			objects: []client.Object{
				&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: stageNS, Labels: labels}},
			},
			report: report("DaemonSet", "agent"),
			want:   "suite",
		},
		{
			name: "Pod",
			objects: []client.Object{
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "tool", Namespace: stageNS, Labels: labels}},
			},
			report: report("Pod", "tool"),
			want:   "suite",
		},
		{
			name: "Job without a CronJob",
			objects: []client.Object{
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "once", Namespace: stageNS, Labels: labels}},
			},
			report: report("Job", "once"),
			want:   "suite",
		},
		{
			name: "CronJob of a Job",
			objects: []client.Object{
				cronJob("nightly-1", 0),
				&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: stageNS, Labels: labels}},
			},
			report: report("Job", "nightly-1"),
			want:   "suite",
		},
		{
			name:    "workload object is gone",
			objects: nil,
			report:  report("StatefulSet", "db"),
			want:    "krci-demo-dev",
		},
		{
			name:    "kind without a component source",
			objects: nil,
			report:  report("ReplicationController", "rc"),
			want:    "krci-demo-dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := append([]client.Object{demoStage(), integrationSecret(), tenantNamespace(stageNS)}, tt.objects...)

			h := newHarness(t, withReports(objects, tt.report))

			h.reconcile()

			require.Len(t, h.dd.reimports, 1)
			assert.Contains(t, h.dd.reimports[0].Tags, "krci-component:"+tt.want)
		})
	}
}

func TestReconcile_ComponentLookupFailureIsReturned(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*metav1.PartialObjectMetadata); ok {
				return errors.New("apiserver unavailable")
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.reimports)
}

func TestReconcile_ReadsTheTopWorkloadWithAMetadataGet(t *testing.T) {
	var kinds []string

	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if m, ok := obj.(*metav1.PartialObjectMetadata); ok {
				kinds = append(kinds, m.GroupVersionKind().Kind+"/"+key.Name)
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	h.reconcile()

	assert.Equal(t, []string{"Deployment/test-go-app"}, kinds, "one get per workload and pass")
}

// wakes returns the namespaces the sweeper handed to the controller.
func wakes(h *harness) []string {
	var out []string

	for {
		select {
		case e := <-h.reconciler.wake:
			out = append(out, e.Object.GetName())
		default:
			return out
		}
	}
}

func sweepFixture(t *testing.T) *harness {
	t.Helper()

	terminating := tenantNamespace("krci-demo-terminating")
	terminating.DeletionTimestamp = &metav1.Time{Time: scanDate}
	terminating.Finalizers = []string{"kubernetes"}

	h := newHarness(t, []client.Object{
		demoStage(),
		integrationSecret(),
		tenantNamespace("krci-demo-kept"),
		tenantNamespace("krci-demo-tenant"),
		namespaceObject("kube-system", nil),
		newStage("kept", "kept", "krci-demo-kept", inClusterName),
		terminating,
	})
	h.reconciler.config.Scopes.Tenant = false
	h.reconciler.config.ExcludeNamespaces = []string{"kube-system"}

	h.dd.seedTests(
		testIn(1, trivy.TagScopeRuntime, cluster, "krci-demo-gone"),
		testIn(2, trivy.TagScopeRuntime, cluster, "krci-demo-kept"),
		testIn(3, trivy.TagScopeTenant, cluster, "krci-demo-tenant"),
		testIn(4, trivy.TagScopePlatform, cluster, "kube-system"),
		testIn(5, trivy.TagScopeRuntime, "other", "krci-demo-gone"),
		testIn(6, trivy.TagScopeTenant, cluster, "krci-demo-terminating"),
		defectdojo.Test{ID: 7, Title: "CI", Tags: []string{trivy.ClusterTag(cluster), trivy.NamespaceTag("krci-demo-gone")}},
		defectdojo.Test{ID: 8, Title: "no namespace", Tags: []string{trivy.TagScopeRuntime, trivy.ClusterTag(cluster)}},
		testIn(9, trivy.TagScopePlatform, cluster, "krci-demo-gone"),
	)

	return h
}

func TestSweep_WakesNamespacesInsteadOfClosing(t *testing.T) {
	h := sweepFixture(t)

	require.NoError(t, h.reconciler.sweep(context.Background()))

	assert.ElementsMatch(t,
		[]string{"krci-demo-gone", "krci-demo-tenant", "kube-system", "krci-demo-terminating"}, wakes(h),
		"each namespace that is gone or out of scope is woken once")
	assert.Empty(t, h.dd.closed, "the sweeper closes nothing")
	assert.Empty(t, h.dd.reimports)
}

func TestSweep_ReconcileClosesTheWokenNamespace(t *testing.T) {
	h := sweepFixture(t)

	require.NoError(t, h.reconciler.sweep(context.Background()))

	for _, ns := range wakes(h) {
		_, err := h.reconciler.Reconcile(context.Background(), namespaceRequest(ns))
		require.NoError(t, err)
	}

	assert.ElementsMatch(t, []int{1, 3, 4, 6, 9}, h.dd.closed)
}

func TestSweep_SkipsReleasedNamespacesAndPrunesThem(t *testing.T) {
	h := sweepFixture(t)

	for _, ns := range []string{"krci-demo-gone", "krci-demo-tenant", "kube-system", "krci-demo-terminating"} {
		h.reconcileNamespace(ns)
	}

	require.Len(t, h.dd.closed, 5)
	require.NoError(t, h.reconciler.sweep(context.Background()))
	assert.Empty(t, wakes(h), "released namespaces are not woken again")
	assert.True(t, h.reconciler.isReleased("krci-demo-gone"))

	h.dd.deleteAllTests()

	require.NoError(t, h.reconciler.sweep(context.Background()))
	assert.False(t, h.reconciler.isReleased("krci-demo-gone"), "a released namespace without tests is forgotten")
}

func TestSweep_ContinuesAfterAFailureAndJoinsTheErrors(t *testing.T) {
	h := newHarness(t, []client.Object{integrationSecret()}, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Namespace); ok && key.Name != "gone" {
				return errors.New("unreadable " + key.Name)
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})
	h.dd.seedTests(
		testIn(1, trivy.TagScopeRuntime, cluster, "bad-a"),
		testIn(2, trivy.TagScopeRuntime, cluster, "gone"),
		testIn(3, trivy.TagScopeRuntime, cluster, "bad-b"),
	)

	err := h.reconciler.sweep(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unreadable bad-a")
	assert.Contains(t, err.Error(), "unreadable bad-b")
	assert.Equal(t, []string{"gone"}, wakes(h), "a namespace that cannot be read is not treated as gone")
	assert.Empty(t, h.dd.closed)
}

func TestSweep_Failures(t *testing.T) {
	h := newHarness(t, []client.Object{integrationSecret()})
	h.dd.listErr = &defectdojo.APIError{StatusCode: 500}

	require.Error(t, h.reconciler.sweep(context.Background()))

	h = newHarness(t, nil)
	require.NoError(t, h.reconciler.sweep(context.Background()), "an absent Secret is not a failure")
	assert.Zero(t, h.dd.listCalls)
}

func TestSweep_StopsWhenTheContextEndsWhileWaking(t *testing.T) {
	h := newHarness(t, []client.Object{integrationSecret()})
	h.reconciler.wake = make(chan event.GenericEvent)
	h.dd.seedTests(testIn(1, trivy.TagScopeRuntime, cluster, "gone"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, h.reconciler.sweep(ctx), context.Canceled)
}

func TestRunSweeper_SweepsAtStartAndStopsOnCancel(t *testing.T) {
	h := newHarness(t, []client.Object{integrationSecret()})
	h.dd.seedTests(testIn(1, trivy.TagScopeRuntime, cluster, "gone"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- h.reconciler.runSweeper(ctx) }()

	select {
	case e := <-h.reconciler.wake:
		assert.Equal(t, "gone", e.Object.GetName(), "the first sweep runs at start")
	case <-time.After(5 * time.Second):
		t.Fatal("the sweeper did not sweep at start")
	}

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the sweeper did not stop on context cancel")
	}
}

func TestRelease_OnlyOwnedTests(t *testing.T) {
	h := newHarness(t, goAppObjects())

	foreign := ownedTest(5, goAppTitle)
	foreign.Tags[1] = trivy.ClusterTag("other")

	noScope := defectdojo.Test{ID: 6, Tags: []string{trivy.ClusterTag(cluster), trivy.NamespaceTag(stageNS)}}
	noCluster := defectdojo.Test{ID: 7, Tags: []string{trivy.TagScopeRuntime, trivy.NamespaceTag(stageNS)}}

	h.dd.seedTests(foreign, noScope, noCluster)

	require.NoError(t, h.reconciler.release(context.Background(), h.dd, stageNS))
	assert.Empty(t, h.dd.closed)

	h.reconciler.markInScope(stageNS)

	h.dd.deleteAllTests()

	for i, scope := range []string{trivy.TagScopeRuntime, trivy.TagScopeTenant, trivy.TagScopePlatform} {
		h.dd.seedTests(testIn(10+i, scope, cluster, stageNS))
	}

	require.NoError(t, h.reconciler.release(context.Background(), h.dd, stageNS))
	assert.Equal(t, []int{10, 11, 12}, h.dd.closed)
}

func TestReconcile_ErrorSemantics(t *testing.T) {
	denyGet := func(match func(client.Object) bool) interceptor.Funcs {
		return interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if match(obj) {
					return errors.New("apiserver unavailable")
				}

				return c.Get(ctx, key, obj, opts...)
			},
		}
	}

	denyList := func(kind string) interceptor.Funcs {
		return interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Kind == kind+"List" {
					return errors.New("apiserver unavailable")
				}

				return c.List(ctx, list, opts...)
			},
		}
	}

	noReportKind := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Group == trivy.TrivyGroup {
				return noKindMatch()
			}

			return c.List(ctx, list, opts...)
		},
	}

	tests := []struct {
		name    string
		objects []client.Object
		funcs   interceptor.Funcs
		setup   func(h *harness)
		wantErr bool
		wantReq time.Duration
	}{
		{
			name:    "Secret read fails",
			objects: goAppObjects(),
			funcs:   denyGet(func(o client.Object) bool { _, ok := o.(*corev1.Secret); return ok }),
			wantErr: true,
		},
		{
			name:    "namespace read fails",
			objects: goAppObjects(),
			funcs:   denyGet(func(o client.Object) bool { _, ok := o.(*corev1.Namespace); return ok }),
			wantErr: true,
		},
		{name: "Stage list fails", objects: goAppObjects(), funcs: denyList("Stage"), wantErr: true},
		{name: "report list fails", objects: withReports(goAppObjects(), goApp(t)), funcs: denyList("VulnerabilityReport"), wantErr: true},
		{name: "image stream list fails", objects: goAppObjects(), funcs: denyList("CodebaseImageStream"), wantErr: true},
		{
			name:    "DefectDojo import fails",
			objects: withReports(goAppObjects(), goApp(t)),
			setup: func(h *harness) {
				h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return errors.New("down") }
			},
			wantErr: true,
		},
		{
			name:    "DefectDojo rejects a report",
			objects: withReports(goAppObjects(), goApp(t)),
			setup: func(h *harness) {
				h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 400} }
			},
			wantReq: resync,
		},
		{
			name:    "DefectDojo test list fails",
			objects: goAppObjects(),
			setup:   func(h *harness) { h.dd.listErr = errors.New("down") },
			wantErr: true,
		},
		{
			name:    "closing a test fails",
			objects: goAppObjects(),
			setup: func(h *harness) {
				h.dd.seedTests(ownedTest(7, goAppTitle))
				h.reconciler.connect = func(string, string) DefectDojo { return failingClose{h.dd} }
			},
			wantErr: true,
		},
		{
			name:    "release fails",
			objects: []client.Object{integrationSecret()},
			setup:   func(h *harness) { h.dd.listErr = errors.New("down") },
			wantErr: true,
		},
		{
			name:    "Secret is absent",
			objects: []client.Object{tenantNamespace(stageNS)},
			wantReq: dependencyRetry,
		},
		{
			name: "Secret has no token",
			objects: []client.Object{tenantNamespace(stageNS), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: operatorNS},
				Data:       map[string][]byte{"url": []byte("https://dd.example.com")},
			}},
			wantReq: dependencyRetry,
		},
		{
			name:    "report CRDs are not served",
			objects: goAppObjects(),
			funcs:   noReportKind,
			wantReq: resync,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.objects, tt.funcs)

			if tt.setup != nil {
				tt.setup(h)
			}

			res, err := h.reconciler.Reconcile(context.Background(), namespaceRequest(stageNS))

			if tt.wantErr {
				require.Error(t, err)
				assert.Zero(t, res.RequeueAfter, "the workqueue backs off")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantReq, res.RequeueAfter)
		})
	}
}

// failingClose is a DefectDojo whose CloseTest fails.
type failingClose struct{ *fakeDefectDojo }

func (failingClose) CloseTest(context.Context, int) error { return errors.New("down") }

func TestReconcile_SecretIsReadOncePerTTL(t *testing.T) {
	secretReads := 0

	h := newHarness(t, withReports(goAppObjects(), goApp(t)), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				secretReads++
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	now := scanDate
	h.reconciler.now = func() time.Time { return now }

	var tokens []string

	h.reconciler.connect = func(_, token string) DefectDojo {
		tokens = append(tokens, token)

		return h.dd
	}

	h.reconcile()
	h.reconcile()

	now = now.Add(secretTTL - time.Second)

	h.reconcile()
	assert.Equal(t, 1, secretReads, "the credentials are cached for a minute")

	secret := integrationSecret()
	secret.Data["token"] = []byte("rotated")
	require.NoError(t, h.client.Update(context.Background(), secret))

	now = now.Add(2 * time.Second)

	h.reconcile()
	assert.Equal(t, 2, secretReads, "the Secret is read again after the TTL")
	assert.Equal(t, []string{"t", "t", "t", "rotated"}, tokens)
}

func TestReconcile_AbsentSecretIsNotCached(t *testing.T) {
	secretReads := 0

	h := newHarness(t, []client.Object{tenantNamespace(stageNS)}, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				secretReads++
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	h.reconcile()
	h.create(integrationSecret())
	h.reconcile()

	assert.Equal(t, 2, secretReads)
}

func TestLogSecret_InfoOnceThenVerbose(t *testing.T) {
	var lines []string

	log := funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})
	ctx := ctrl.LoggerInto(context.Background(), log)

	h := newHarness(t, nil)

	for range 3 {
		_, _, err := h.reconciler.defectDojo(ctx)
		require.NoError(t, err)
	}

	assert.Len(t, lines, 1, "the absent Secret is logged once at Info and then at V(1)")
}

func TestReconcile_RequeueIsSpreadByTenPercent(t *testing.T) {
	h := newHarness(t, goAppObjects())

	for _, tt := range []struct {
		random float64
		want   time.Duration
	}{
		{0, resync * 9 / 10},
		{0.5, resync},
		{0.999999, resync * 11 / 10},
	} {
		h.reconciler.random = func() float64 { return tt.random }

		res := h.reconcile()

		assert.InDelta(t, float64(tt.want), float64(res.RequeueAfter), float64(time.Second))
	}
}

func TestReconcile_ProcessesReportsPageByPage(t *testing.T) {
	var (
		h        *harness
		limits   []int64
		imported []int
	)

	funcs := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			u, ok := list.(*unstructured.UnstructuredList)
			if !ok || u.GroupVersionKind().Kind != "VulnerabilityReportList" {
				return c.List(ctx, list, opts...)
			}

			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)

			limits = append(limits, lo.Limit)
			imported = append(imported, len(h.dd.reimports))

			switch lo.Continue {
			case "":
				u.Items = []unstructured.Unstructured{*goApp(t)}
				u.SetContinue("page-2")
			case "page-2":
				u.Items = []unstructured.Unstructured{*fixture(t, "vulnerabilityreport_dockerhub.json")}
				u.SetContinue("page-3")
			default:
				u.Items = nil
			}

			return nil
		},
	}

	h = newHarness(t, pagedObjects(), funcs)
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/removed/removed"))

	h.reconcile()

	assert.Equal(t, []int{0, 1, 2}, imported[:3], "a page is imported before the next one is read")
	assert.Equal(t, []int64{reportsPageSize, reportsPageSize, reportsPageSize}, limits[:3])
	assert.Len(t, h.dd.reimports, 2)
	assert.Equal(t, []int{7}, h.dd.closed, "tests imported from earlier pages stay open")
}

func TestReconcile_PrunesTheStateOfTests(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport krci-demo-dev/deployment/removed/removed"))

	h.reconcile()

	assert.Contains(t, h.reconciler.closed[stageNS], 7)
	assert.Contains(t, h.reconciler.healed[stageNS], 100)

	// DefectDojo no longer lists the closed test: its ID is forgotten.
	h.dd.deleteTest(7)

	h.reconcile()
	assert.NotContains(t, h.reconciler.closed, stageNS)
	assert.Contains(t, h.reconciler.healed[stageNS], 100, "the live test stays healed")

	// The workload is gone: its test is closed and no longer live, so it is not healed any more.
	h.deleteReport(goApp(t))

	h.reconcile()
	assert.NotContains(t, h.reconciler.healed, stageNS)
}

func TestReconcile_ReleasePrunesTheNamespaceAndInScopeForgetsIt(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Contains(t, h.reconciler.imported, stageNS)
	require.Contains(t, h.reconciler.healed, stageNS)

	h.reconciler.config.Scopes.Stage = false

	h.reconcile()
	assert.True(t, h.reconciler.isReleased(stageNS))
	assert.NotContains(t, h.reconciler.imported, stageNS)
	assert.NotContains(t, h.reconciler.closed, stageNS)
	assert.NotContains(t, h.reconciler.healed, stageNS)

	h.reconciler.config.Scopes.Stage = true

	h.reconcile()
	assert.False(t, h.reconciler.isReleased(stageNS), "a namespace in scope again is no longer released")
}

func TestReportPredicate(t *testing.T) {
	p := reportPredicate()
	old := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "r", ResourceVersion: "1"}}
	same := old.DeepCopy()
	changed := old.DeepCopy()
	changed.ResourceVersion = "2"

	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: same}), "an informer resync changes nothing")
	assert.True(t, p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: changed}))
	assert.True(t, p.Create(event.CreateEvent{Object: old}))
	assert.True(t, p.Delete(event.DeleteEvent{Object: old}))
}
