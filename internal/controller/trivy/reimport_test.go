package trivy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	cveKept       = "CVE-2026-14456 libcrypto3 3.5.6-r0"
	cveFixed      = "CVE-2026-45447 libcrypto3 3.5.6-r0"
	cveKeptNewPkg = "CVE-2026-14456 libcrypto3 3.5.6-r1"
)

// onlyTest reconciles once and returns the ID of the one test the pass wrote.
func (h *harness) onlyTest() int {
	h.t.Helper()

	h.reconcile()

	ids := h.dd.testIDs()
	require.Len(h.t, ids, 1)

	return ids[0]
}

// withArtifact returns the go app report with the given image fields.
func withArtifact(t *testing.T, fields map[string]string) *unstructured.Unstructured {
	t.Helper()

	report := goApp(t)

	for field, value := range fields {
		require.NoError(t, unstructured.SetNestedField(report.Object, value, "report", "artifact", field))
	}

	return report
}

func TestReconcile_NewImageTagWithTheSamePackagesKeepsEveryFinding(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()

	before := h.dd.findingsIn(testID)
	require.Len(t, before, 2)

	h.setReport(withArtifact(t, map[string]string{"tag": "main-20261111-101010", "digest": "sha256:0123456789abcdef"}))

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, h.dd.reimports[0].Service, h.dd.reimports[1].Service, "the service does not depend on the image")
	assert.Equal(t, before, h.dd.findingsIn(testID), "the same findings stay active, none is closed or added")
	assert.Equal(t, "main-20261111-101010", h.dd.test(testID).version)
}

func TestReconcile_PackageUpgradeThatIsStillVulnerableClosesTheOldFindingAndOpensANewOne(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()

	next := goApp(t)
	vulns, _, err := unstructured.NestedSlice(next.Object, "report", "vulnerabilities")
	require.NoError(t, err)

	first, ok := vulns[0].(map[string]any)
	require.True(t, ok)

	first["installedVersion"] = "3.5.6-r1"

	require.NoError(t, unstructured.SetNestedSlice(next.Object, vulns, "report", "vulnerabilities"))
	h.setReport(next)

	h.reconcile()

	assert.Equal(t, map[string]string{
		cveKept:       statusClosed,
		cveKeptNewPkg: statusActive,
		cveFixed:      statusActive,
	}, h.dd.statuses(testID, goAppService))
}

func TestReconcile_RolloutKeepsTheFindingsInTheSameTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()

	before := h.dd.findingsIn(testID)

	h.create(replicaSet("test-go-app-new", "test-go-app", "2"))

	dep := &appsv1.Deployment{}
	require.NoError(t, h.client.Get(t.Context(), client.ObjectKey{Namespace: appNS, Name: "test-go-app"}, dep))
	dep.Annotations[revisionAnnotation] = "2"
	require.NoError(t, h.client.Update(t.Context(), dep))

	next := withArtifact(t, map[string]string{"tag": "main-20261112-090909"})
	next.SetName("replicaset-test-go-app-new-test-go-app")
	next.SetUID("uid-new")
	next.SetLabels(map[string]string{
		trivy.LabelResourceKind:      "ReplicaSet",
		trivy.LabelResourceName:      "test-go-app-new",
		trivy.LabelResourceNamespace: appNS,
		trivy.LabelContainerName:     "test-go-app",
	})
	next.SetResourceVersion("")
	h.setReport(next)

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, h.dd.reimports[0].Service, h.dd.reimports[1].Service, "the service is stable across the rollout")
	assert.Equal(t, []int{testID}, h.dd.testIDs(), "the new ReplicaSet writes into the same test")
	assert.Equal(t, before, h.dd.findingsIn(testID))
}

func TestReconcile_TestCarriesExactlyTheTagsOfItsWorkloadAndImage(t *testing.T) {
	const image = "oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app"

	t.Run("a workload without a component source has no app tag", func(t *testing.T) {
		h := newHarness(t, withReports(goAppObjects(), goApp(t)))
		testID := h.onlyTest()

		assert.Equal(t, []string{
			"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
			"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app", image,
		}, h.dd.test(testID).tags)
	})

	t.Run("a workload with a component source has one app tag", func(t *testing.T) {
		objects := goAppObjects()
		objects[goAppDeployment] = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Name: "test-go-app", Namespace: appNS, Labels: map[string]string{"app.kubernetes.io/part-of": "Shop"},
			Annotations: map[string]string{revisionAnnotation: "1"},
		}}

		h := newHarness(t, withReports(objects, goApp(t)))
		testID := h.onlyTest()

		assert.Equal(t, []string{
			"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
			"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app", image, "app:shop",
		}, h.dd.test(testID).tags)
	})

	t.Run("another image replaces the image tag", func(t *testing.T) {
		h := newHarness(t, withReports(goAppObjects(), goApp(t)))
		testID := h.onlyTest()

		h.setReport(withArtifact(t, map[string]string{"repository": "krci/other-app"}))

		h.reconcile()

		assert.Equal(t, []string{
			"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
			"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app",
			"oci-image:gitlab.127.0.0.1.nip.io:5050/krci/other-app",
		}, h.dd.test(testID).tags)
	})

	t.Run("an exposed secret report has the same tags", func(t *testing.T) {
		h := newHarness(t, withReports(goAppObjects(), goAppSecrets(t)))
		testID := h.onlyTest()

		assert.Equal(t, []string{
			"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
			"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app", image,
		}, h.dd.test(testID).tags)
	})
}

func TestReconcile_VersionIsTheImageTagOrTheDigestPrefix(t *testing.T) {
	tests := map[string]struct {
		artifact map[string]string
		want     string
	}{
		"tag":         {artifact: nil, want: "main-20261110-194848"},
		"digest only": {artifact: map[string]string{"tag": ""}, want: "sha256:9155b03ee4d9"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), withArtifact(t, tt.artifact)))
			testID := h.onlyTest()

			assert.Equal(t, tt.want, h.dd.test(testID).version)
		})
	}
}

func TestReconcile_VersionOverTheLimitIsShortenedTheSameOnEveryPass(t *testing.T) {
	long := strings.Repeat("v", 150)

	h := newHarness(t, withReports(goAppObjects(), withArtifact(t, map[string]string{"tag": long})))
	testID := h.onlyTest()

	version := h.dd.test(testID).version
	assert.Len(t, version, trivy.MaxVersionLen)
	assert.True(t, strings.HasPrefix(version, strings.Repeat("v", 87)+"~"))

	h.setReport(withArtifact(t, map[string]string{"tag": long}))

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, version, h.dd.test(testID).version)
}

// A workload with a long name: the ReplicaSet name is not a valid label value, so Trivy Operator writes it only to
// the annotation. The service, the title and the workload tag are over their limits and are shortened; DefectDojo
// rejects a longer value.
func TestReconcile_LongWorkloadNameKeepsOneTestAndItsFindings(t *testing.T) {
	name := strings.Repeat("w", 240)
	replicaSetName := name + "-9dc66c9c6"

	newReport := func() *unstructured.Unstructured {
		report := goApp(t)
		report.SetLabels(map[string]string{
			trivy.LabelResourceKind:      "ReplicaSet",
			trivy.LabelResourceNamespace: appNS,
			trivy.LabelContainerName:     "test-go-app",
		})
		report.SetAnnotations(map[string]string{trivy.LabelResourceName: replicaSetName})

		return report
	}

	objects := []client.Object{
		integrationSecret(), namespaceObject(appNS, nil), deployment(name, "1"), replicaSet(replicaSetName, name, "1"),
	}

	h := newHarness(t, withReports(objects, newReport()))
	testID := h.onlyTest()

	require.Len(t, h.dd.reimports, 1)

	req := h.dd.reimports[0]
	assert.Len(t, req.Service, trivy.MaxServiceLen)
	assert.Len(t, req.TestTitle, trivy.MaxTitleLen)
	assert.Equal(t, map[string]string{cveKept: statusActive, cveFixed: statusActive}, h.dd.statuses(testID, req.Service))

	wantTag := "k8s-workload:" + trivy.Shorten("deployment."+name, trivy.MaxTagLen-len("k8s-workload:"))
	assert.Len(t, wantTag, trivy.MaxTagLen)
	assert.Contains(t, h.dd.test(testID).tags, wantTag, "the tag value is shortened and keeps its key")

	before := h.dd.findingsIn(testID)

	h.setReport(newReport())

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, req.Service, h.dd.reimports[1].Service, "the service is the same on every pass")
	assert.Equal(t, req.TestTitle, h.dd.reimports[1].TestTitle)
	assert.Equal(t, []int{testID}, h.dd.testIDs())
	assert.Equal(t, before, h.dd.findingsIn(testID))
}
