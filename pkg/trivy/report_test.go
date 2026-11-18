package trivy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

func loadFixture(t *testing.T, name string) *unstructured.Unstructured {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	obj := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &obj))

	return &unstructured.Unstructured{Object: obj}
}

func testTarget() Target {
	return Target{Namespace: testNamespace, Cluster: "in-cluster"}
}

func TestReportImport(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		workload Workload
		want     Import
	}{
		{
			name:     "vulnerability report of a Deployment container",
			fixture:  "vulnerabilityreport_replicaset.json",
			workload: Workload{"deployment", "test-go-app"},
			want: Import{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "VulnerabilityReport deployment/test-go-app/test-go-app",
				Version:    "main-20261110-194848",
				Tags: []string{
					"krci-namespace:krci-demo-dev",
					"krci-workload:deployment.test-go-app", "krci-container:test-go-app",
					"krci-component:go-app", "krci-cluster:in-cluster",
				},
			},
		},
		{
			name:     "image of a foreign registry",
			fixture:  "vulnerabilityreport_dockerhub.json",
			workload: Workload{"deployment", "defectdojo-primary"},
			want: Import{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "VulnerabilityReport deployment/defectdojo-primary/postgres",
				Version:    "16-alpine",
				Tags: []string{
					"krci-namespace:krci-demo-dev",
					"krci-workload:deployment.defectdojo-primary", "krci-container:postgres",
					"krci-component:go-app", "krci-cluster:in-cluster",
				},
			},
		},
		{
			name:     "whole image reference in the tag is versioned by its tag",
			fixture:  "vulnerabilityreport_fullref_tag.json",
			workload: Workload{"statefulset", "defectdojo-valkey"},
			want: Import{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "VulnerabilityReport statefulset/defectdojo-valkey/valkey",
				Version:    "9.0.0-alpine3.22",
				Tags: []string{
					"krci-namespace:krci-demo-dev",
					"krci-workload:statefulset.defectdojo-valkey", "krci-container:valkey",
					"krci-component:go-app", "krci-cluster:in-cluster",
				},
			},
		},
		{
			name:     "exposed secret report has its own test in the same product",
			fixture:  "exposedsecretreport_replicaset.json",
			workload: Workload{"deployment", "test-go-app"},
			want: Import{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "ExposedSecretReport deployment/test-go-app/test-go-app",
				Version:    "main-20261110-194848",
				Tags: []string{
					"krci-namespace:krci-demo-dev",
					"krci-workload:deployment.test-go-app", "krci-container:test-go-app",
					"krci-component:go-app", "krci-cluster:in-cluster",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReportImport(testTarget(), loadFixture(t, tt.fixture), tt.workload, "go-app")

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReportImport_ProductNamesTheClusterAndTheNamespace(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	workload := Workload{"deployment", "test-go-app"}

	a := ReportImport(Target{Namespace: "payments", Cluster: "prod-eu"}, report, workload, "x")
	b := ReportImport(Target{Namespace: "payments", Cluster: "prod-us"}, report, workload, "x")

	assert.Equal(t, "prod-eu/payments", a.Product)
	assert.Equal(t, "prod-us/payments", b.Product, "the same namespace name in two clusters gives two products")
	assert.Equal(t, a.TestTitle, b.TestTitle, "the title has no namespace")
}

func TestReportImport_VersionFallsBackToDigest(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	require.NoError(t, unstructured.SetNestedField(report.Object, "", "report", "artifact", "tag"))

	got := ReportImport(testTarget(), report, Workload{"deployment", "app"}, "app")

	assert.Equal(t, "sha256:9155b03ee4d9", got.Version)
}

func TestImport_Request(t *testing.T) {
	scanDate := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	i := Import{Product: "p", Engagement: "e", TestTitle: "t", Version: "v", Tags: []string{"a"}}

	req := i.Request("KubeRocketCI", scanDate, []byte("{}"))

	assert.Equal(t, "KubeRocketCI", req.ProductType)
	assert.Equal(t, "p", req.Product)
	assert.Equal(t, "e", req.Engagement)
	assert.Equal(t, "t", req.TestTitle)
	assert.Equal(t, "v", req.Version)
	assert.Equal(t, []string{"a"}, req.Tags)
	assert.Equal(t, scanDate, req.ScanDate)
	assert.Equal(t, []byte("{}"), req.Report)
}

func TestPayload(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	require.NoError(t, unstructured.SetNestedSlice(report.Object, []any{map[string]any{"manager": "x"}}, "metadata", "managedFields"))

	tests := []struct {
		name     string
		workload Workload
		kind     string
		resource string
		service  string
	}{
		{
			name:     "replicaset becomes its deployment",
			workload: Workload{"deployment", "test-go-app"},
			kind:     "Deployment", resource: "test-go-app",
			service: "krci-demo-dev/Deployment/test-go-app/test-go-app",
		},
		{
			name:     "job becomes its cronjob",
			workload: Workload{"cronjob", "nightly"},
			kind:     "CronJob", resource: "nightly",
			service: "krci-demo-dev/CronJob/nightly/test-go-app",
		},
		{
			name:     "other kinds are unchanged",
			workload: Workload{"statefulset", "db"},
			kind:     "ReplicaSet", resource: "test-go-app-9dc66c9c6",
			service: "krci-demo-dev/ReplicaSet/test-go-app-9dc66c9c6/test-go-app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := Payload(report, tt.workload)
			sent := &unstructured.Unstructured{Object: payload}

			_, found, _ := unstructured.NestedFieldNoCopy(payload, "metadata", "managedFields")
			assert.False(t, found)
			assert.Equal(t, "VulnerabilityReport", payload["kind"])
			assert.Contains(t, payload, "report")
			assert.Equal(t, tt.kind, sent.GetLabels()[LabelResourceKind])
			assert.Equal(t, tt.resource, sent.GetLabels()[LabelResourceName])
			assert.Equal(t, "test-go-app", sent.GetLabels()[LabelContainerName])
			assert.Equal(t, tt.service, Service(report, tt.workload))
		})
	}

	_, found, _ := unstructured.NestedFieldNoCopy(report.Object, "metadata", "managedFields")
	assert.True(t, found, "the report is not modified")
	assert.Equal(t, "ReplicaSet", report.GetLabels()[LabelResourceKind])
}

func TestReportGVK(t *testing.T) {
	gvk := ReportGVK(KindExposedSecretReport)

	assert.Equal(t, "aquasecurity.github.io", gvk.Group)
	assert.Equal(t, "v1alpha1", gvk.Version)
	assert.Equal(t, "ExposedSecretReport", gvk.Kind)
}

func TestImportTitle(t *testing.T) {
	assert.Equal(t, "VulnerabilityReport deployment/app/web",
		ImportTitle("VulnerabilityReport", Workload{"deployment", "app"}, "web"))
	assert.Equal(t, "ExposedSecretReport cronjob/nightly/job",
		ImportTitle("ExposedSecretReport", Workload{"cronjob", "nightly"}, "job"))
}

func TestReportTitle_IsTheTitleOfTheImport(t *testing.T) {
	workload := Workload{"deployment", "test-go-app"}

	for _, fixture := range []string{"vulnerabilityreport_replicaset.json", "exposedsecretreport_replicaset.json"} {
		report := loadFixture(t, fixture)

		assert.Equal(t, ReportImport(testTarget(), report, workload, "go-app").TestTitle, ReportTitle(report, workload))
	}
}

func TestTitleKind(t *testing.T) {
	w := Workload{"deployment", "app"}

	for _, kind := range ReportKinds {
		assert.Equal(t, kind, TitleKind(ImportTitle(kind, w, "web")))
	}

	assert.Equal(t, "Trivy", TitleKind("Trivy Scan"), "a title written elsewhere yields its first word")
	assert.Empty(t, TitleKind(""))
}

func TestNamespaceTag(t *testing.T) {
	assert.Equal(t, "krci-namespace:ns-a", NamespaceTag("ns-a"))
}

func TestIsOwned(t *testing.T) {
	test := func(product, scanType string) defectdojo.Test {
		return defectdojo.Test{Product: product, ScanType: scanType}
	}

	const trivyScan = defectdojo.ScanTypeTrivyOperator

	assert.True(t, IsOwned(test("c1/ns", trivyScan), "c1"))
	assert.False(t, IsOwned(test("c2/ns", trivyScan), "c1"), "another cluster")
	assert.False(t, IsOwned(test("x-c1/ns", trivyScan), "c1"), "the product name contains the prefix but does not start with it")
	assert.False(t, IsOwned(test("c1", trivyScan), "c1"), "a codebase product named like the cluster")
	assert.False(t, IsOwned(test("c1/ns", "Trivy Scan"), "c1"), "another scan type")
	assert.False(t, IsOwned(defectdojo.Test{ScanType: trivyScan}, "c1"), "no product")
}

func TestNamespaceOfProduct(t *testing.T) {
	ns, ok := NamespaceOfProduct("c1", "c1/payments")
	assert.True(t, ok)
	assert.Equal(t, "payments", ns)

	for _, name := range []string{"c1/", "c1", "c2/payments", "x-c1/payments", "c1/a/b", "payments"} {
		_, ok = NamespaceOfProduct("c1", name)
		assert.False(t, ok, name)
	}
}

func TestWithProductTags(t *testing.T) {
	tests := []struct {
		name        string
		have        []string
		want        []string
		wantChanged bool
	}{
		{
			name:        "no tags",
			want:        []string{"k8s-cluster:c1", "k8s-namespace:ns"},
			wantChanged: true,
		},
		{
			name: "both tags in any order",
			have: []string{"k8s-namespace:ns", "k8s-cluster:c1"},
			want: []string{"k8s-cluster:c1", "k8s-namespace:ns"},
		},
		{
			name:        "other tags are kept",
			have:        []string{"owner:team-a", "k8s-cluster:c1"},
			want:        []string{"owner:team-a", "k8s-cluster:c1", "k8s-namespace:ns"},
			wantChanged: true,
		},
		{
			name:        "a wrong value is replaced, one tag per key",
			have:        []string{"k8s-cluster:old", "k8s-cluster:c1", "k8s-namespace:other", "owner:team-a"},
			want:        []string{"owner:team-a", "k8s-cluster:c1", "k8s-namespace:ns"},
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := WithProductTags(tt.have, "c1", "ns")

			assert.ElementsMatch(t, tt.want, got)
			assert.Equal(t, tt.wantChanged, changed)
		})
	}
}

func TestPayload_DoesNotModifyTheReport(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	require.NoError(t, unstructured.SetNestedSlice(report.Object, []any{map[string]any{"manager": "x"}}, "metadata", "managedFields"))

	payload := Payload(report, Workload{"deployment", "test-go-app"})

	metadata := payload["metadata"].(map[string]any)
	assert.NotContains(t, metadata, "managedFields")
	assert.Equal(t, "Deployment", metadata["labels"].(map[string]any)[LabelResourceKind])

	assert.Contains(t, report.Object["metadata"], "managedFields")
	assert.Equal(t, "ReplicaSet", report.GetLabels()[LabelResourceKind])
}
