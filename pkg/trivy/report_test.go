package trivy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

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

// newReimport is NewReimport with the kind and the image of the report, for a container without a known reference.
func newReimport(target Target, report *unstructured.Unstructured, workload Workload, component string) Reimport {
	return NewReimport(target, report.GetKind(), report, workload, component, ReportImage(report))
}

func TestReportImport(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		workload  Workload
		component string
		want      Reimport
	}{
		{
			name:      "vulnerability report of a Deployment container",
			fixture:   "vulnerabilityreport_replicaset.json",
			workload:  Workload{"deployment", "test-go-app"},
			component: "go-app",
			want: Reimport{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "VulnerabilityReport deployment/test-go-app/test-go-app",
				Service:    "krci-demo-dev/Deployment/test-go-app/test-go-app",
				Version:    "main-20261110-194848",
				Tags: []string{
					"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
					"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app",
					"oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app", "app:go-app",
					"report-kind:vulnerabilityreport",
				},
			},
		},
		{
			name:      "image of Docker Hub is written without host and library",
			fixture:   "vulnerabilityreport_dockerhub.json",
			workload:  Workload{"deployment", "defectdojo-primary"},
			component: "go-app",
			want: Reimport{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "VulnerabilityReport deployment/defectdojo-primary/postgres",
				Service:    "defectdojo/Deployment/defectdojo-primary/postgres",
				Version:    "16-alpine",
				Tags: []string{
					"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
					"k8s-workload:deployment.defectdojo-primary", "k8s-container:postgres",
					"oci-image:postgres", "app:go-app", "report-kind:vulnerabilityreport",
				},
			},
		},
		{
			name:     "whole image reference in the tag is versioned by its tag, no app tag without a component",
			fixture:  "vulnerabilityreport_fullref_tag.json",
			workload: Workload{"statefulset", "defectdojo-valkey"},
			want: Reimport{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "VulnerabilityReport statefulset/defectdojo-valkey/valkey",
				Service:    "defectdojo/StatefulSet/defectdojo-valkey/valkey",
				Version:    "9.0.0-alpine3.22",
				Tags: []string{
					"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
					"k8s-workload:statefulset.defectdojo-valkey", "k8s-container:valkey",
					"oci-image:valkey/valkey", "report-kind:vulnerabilityreport",
				},
			},
		},
		{
			name:      "exposed secret report has its own test in the same product",
			fixture:   "exposedsecretreport_replicaset.json",
			workload:  Workload{"deployment", "test-go-app"},
			component: "go-app",
			want: Reimport{
				Product:    "in-cluster/krci-demo-dev",
				Engagement: "trivy-operator",
				TestTitle:  "ExposedSecretReport deployment/test-go-app/test-go-app",
				Service:    "krci-demo-dev/Deployment/test-go-app/test-go-app",
				Version:    "main-20261110-194848",
				Tags: []string{
					"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
					"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app",
					"oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app", "app:go-app",
					"report-kind:exposedsecretreport",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newReimport(testTarget(), loadFixture(t, tt.fixture), tt.workload, tt.component)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReportImport_TagValuesAreTagSafe(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")

	got := newReimport(Target{Namespace: "Team A,B", Cluster: "Prod EU"}, report, Workload{"deployment", "app"}, "My,App x")

	assert.Contains(t, got.Tags, "k8s-cluster:prod-eu")
	assert.Contains(t, got.Tags, "k8s-namespace:team-a-b")
	assert.Contains(t, got.Tags, "app:my-app-x")
}

func TestReportImport_OneTagPerKey(t *testing.T) {
	got := newReimport(testTarget(), loadFixture(t, "vulnerabilityreport_replicaset.json"), Workload{"deployment", "app"}, "x")

	keys := map[string]int{}

	for _, tag := range got.Tags {
		key, _, _ := strings.Cut(tag, ":")
		keys[key]++
	}

	assert.Equal(t, map[string]int{
		"k8s-cluster": 1, "k8s-namespace": 1, "k8s-workload": 1, "k8s-container": 1, "oci-image": 1, "app": 1,
		"report-kind": 1,
	}, keys)
}

func TestReportImport_ProductNamesTheClusterAndTheNamespace(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	workload := Workload{"deployment", "test-go-app"}

	a := newReimport(Target{Namespace: "payments", Cluster: "prod-eu"}, report, workload, "x")
	b := newReimport(Target{Namespace: "payments", Cluster: "prod-us"}, report, workload, "x")

	assert.Equal(t, "prod-eu/payments", a.Product)
	assert.Equal(t, "prod-us/payments", b.Product, "the same namespace name in two clusters gives two products")
	assert.Equal(t, a.TestTitle, b.TestTitle, "the title has no namespace")
}

func TestReportImport_Version(t *testing.T) {
	longTag := strings.Repeat("t", 150)

	tests := map[string]struct {
		tag, digest, want string
	}{
		"tag":                 {tag: "1.2", digest: "sha256:9155b03ee4d94b88", want: "1.2"},
		"digest only":         {digest: "sha256:9155b03ee4d94b88f7ef", want: "sha256:9155b03ee4d9"},
		"short digest":        {digest: "sha256:9155", want: "sha256:9155"},
		"digest without algo": {digest: "9155b03ee4d94b88", want: "sha256:9155b03ee4d9"},
		"no tag, no digest":   {want: ""},
		"tag over the limit":  {tag: longTag, want: Shorten(longTag, MaxVersionLen)},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			report := loadFixture(t, "vulnerabilityreport_replicaset.json")
			require.NoError(t, unstructured.SetNestedField(report.Object, tt.tag, "report", "artifact", "tag"))
			require.NoError(t, unstructured.SetNestedField(report.Object, tt.digest, "report", "artifact", "digest"))

			got := newReimport(testTarget(), report, Workload{"deployment", "app"}, "app")

			assert.Equal(t, tt.want, got.Version)
			assert.LessOrEqual(t, len(got.Version), MaxVersionLen)
		})
	}
}

func TestReportImport_LongNamesKeepTheirLimits(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	name := strings.Repeat("n", 250)
	workload := Workload{"deployment", name}

	labels := report.GetLabels()
	labels[LabelResourceKind] = "Deployment"
	labels[LabelResourceName] = name
	report.SetLabels(labels)

	got := newReimport(testTarget(), report, workload, "app")

	assert.Len(t, got.Service, MaxServiceLen)
	assert.Len(t, got.TestTitle, MaxTitleLen)
	assert.True(t, strings.HasPrefix(got.TestTitle, "VulnerabilityReport deployment/nnn"))
	assert.Equal(t, got, newReimport(testTarget(), report, workload, "app"), "the same input gives the same values")
	assert.Equal(t, ReportTitle(report.GetKind(), report, workload), got.TestTitle)
	assert.Equal(t, KindVulnerabilityReport, TitleKind(got.TestTitle))
}

func TestReportImport_TagOverTheLimitIsShortenedKeepingItsKey(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	name := strings.Repeat("n", 240)
	value := "deployment." + name

	got := newReimport(testTarget(), report, Workload{"deployment", name}, "app")

	want := TagKeyWorkload + ":" + Shorten(value, MaxTagLen-len(TagKeyWorkload)-1)
	assert.Contains(t, got.Tags, want)
	assert.Len(t, want, MaxTagLen)
	assert.True(t, strings.HasPrefix(want, "k8s-workload:deployment.nnn"))

	for _, tag := range got.Tags {
		assert.LessOrEqual(t, len(tag), MaxTagLen, tag)
	}

	assert.Equal(t, got.Tags, newReimport(testTarget(), report, Workload{"deployment", name}, "app").Tags,
		"the same input gives the same tags")
}

func TestReportImport_TagAtTheLimitIsKept(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	name := strings.Repeat("n", MaxTagLen-len(TagKeyWorkload)-1-len("deployment."))

	got := newReimport(testTarget(), report, Workload{"deployment", name}, "app")

	assert.Contains(t, got.Tags, "k8s-workload:deployment."+name)
}

func TestReportImport_TagsHoldNoCharacterDefectDojoRejects(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")

	got := newReimport(Target{Namespace: "ns", Cluster: `c'1"x`}, report, Workload{"deployment", "app"}, `My'App "x"`)

	assert.Contains(t, got.Tags, "k8s-cluster:c-1-x")
	assert.Contains(t, got.Tags, "app:my-app--x-")

	for _, tag := range got.Tags {
		assert.NotContains(t, tag, "'")
		assert.NotContains(t, tag, `"`)
	}
}

func TestImport_Request(t *testing.T) {
	scanDate := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	i := Reimport{Product: "p", Engagement: "e", TestTitle: "t", Service: "s", Version: "v", Tags: []string{"a"}}

	req := i.Request("KubeRocketCI", scanDate, "uid:1:abc", []byte("{}"))

	assert.Equal(t, "KubeRocketCI", req.ProductType)
	assert.Equal(t, "p", req.Product)
	assert.Equal(t, "e", req.Engagement)
	assert.Equal(t, "t", req.TestTitle)
	assert.Equal(t, "s", req.Service)
	assert.Equal(t, "v", req.Version)
	assert.Equal(t, "uid:1:abc", req.BuildID)
	assert.Equal(t, []string{"a"}, req.Tags)
	assert.Equal(t, scanDate, req.ScanDate)
	assert.Equal(t, []byte("{}"), req.Report)
}

func markedReport(uid, resourceVersion string) *unstructured.Unstructured {
	report := &unstructured.Unstructured{Object: map[string]any{}}
	report.SetUID(types.UID(uid))
	report.SetResourceVersion(resourceVersion)

	return report
}

func TestUploadMarker_IsTheReportVersionAndAHashOfTheRequest(t *testing.T) {
	i := Reimport{TestTitle: "t", Service: "s", Version: "v", Tags: []string{"a:1", "b:2"}}
	uid := "0f7b2c1e-4d3a-4b8e-9c55-1a2b3c4d5e6f"

	marker := i.UploadMarker(markedReport(uid, "4711"))

	assert.Regexp(t, `^`+uid+`:4711:[0-9a-f]{12}$`, marker)
	assert.Equal(t, marker, i.UploadMarker(markedReport(uid, "4711")), "the same report version gives the same marker")
	assert.NotEqual(t, marker, i.UploadMarker(markedReport(uid, "4712")), "another resourceVersion")
	assert.NotEqual(t, marker, i.UploadMarker(markedReport("another-uid", "4711")), "another UID")
}

func TestUploadMarker_ChangesWithWhatTheRequestSends(t *testing.T) {
	report := markedReport("uid", "1")
	base := Reimport{TestTitle: "t", Service: "s", Version: "v", Tags: []string{"a:1", "b:2"}}

	for name, changed := range map[string]Reimport{
		"title":   {TestTitle: "t2", Service: "s", Version: "v", Tags: []string{"a:1", "b:2"}},
		"service": {TestTitle: "t", Service: "s2", Version: "v", Tags: []string{"a:1", "b:2"}},
		"version": {TestTitle: "t", Service: "s", Version: "v2", Tags: []string{"a:1", "b:2"}},
		"a tag":   {TestTitle: "t", Service: "s", Version: "v", Tags: []string{"a:1", "b:3"}},
		"no tag":  {TestTitle: "t", Service: "s", Version: "v", Tags: []string{"a:1"}},
		"a tag moved to another field": {
			TestTitle: "t", Service: "s", Version: "v" + "\x00a:1", Tags: []string{"b:2"},
		},
	} {
		assert.NotEqual(t, base.UploadMarker(report), changed.UploadMarker(report), name)
	}

	reordered := Reimport{TestTitle: "t", Service: "s", Version: "v", Tags: []string{"b:2", "a:1"}}
	assert.Equal(t, base.UploadMarker(report), reordered.UploadMarker(report), "the order of the tags does not matter")
}

func TestUploadMarker_ChangesWithTheRequestFormat(t *testing.T) {
	i := Reimport{TestTitle: "t", Service: "s", Version: "v", Tags: []string{"a:1"}}

	assert.NotEqual(t, i.fingerprint(requestFormat), i.fingerprint(requestFormat+1),
		"a changed payload or constant field gives another marker for every report")
	assert.True(t, strings.HasSuffix(i.UploadMarker(markedReport("uid", "1")), ":"+i.fingerprint(requestFormat)))
}

func TestUploadMarker_FitsTheBuildIDLimit(t *testing.T) {
	i := Reimport{TestTitle: "t", Service: "s", Version: "v"}
	uid := "0f7b2c1e-4d3a-4b8e-9c55-1a2b3c4d5e6f"

	// An etcd resourceVersion has at most 20 digits; the API does not promise that.
	atLimit := strings.Repeat("9", MaxBuildIDLen-len(uid)-len(":")-len(":")-hashLen)
	assert.Len(t, i.UploadMarker(markedReport(uid, atLimit)), MaxBuildIDLen)
	assert.True(t, strings.HasPrefix(i.UploadMarker(markedReport(uid, atLimit)), uid+":"+atLimit+":"))

	long := markedReport(uid, strings.Repeat("9", 500))
	marker := i.UploadMarker(long)

	assert.Len(t, marker, MaxBuildIDLen)
	assert.Equal(t, marker, i.UploadMarker(long), "a shortened marker is the same on every pass")
	assert.NotEqual(t, marker, i.UploadMarker(markedReport(uid, strings.Repeat("9", 499)+"8")),
		"a shortened marker still tells report versions apart")
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

// parserService is the finding service of the Trivy Operator parser: "<namespace>/<kind>/<name>" of the report
// labels, then "/<container>" when the container label is not empty.
func parserService(labels map[string]string) string {
	service := labels[LabelResourceNamespace] + "/" + labels[LabelResourceKind] + "/" + labels[LabelResourceName]

	if container := labels[LabelContainerName]; container != "" {
		service += "/" + container
	}

	return service
}

func TestPayload_ServiceIsTheOneTheParserBuildsFromTheLabels(t *testing.T) {
	withoutNamespaceLabel := func() *unstructured.Unstructured {
		report := loadFixture(t, "vulnerabilityreport_replicaset.json")
		report.SetLabels(withoutKey(report.GetLabels(), LabelResourceNamespace))
		report.SetNamespace("report-ns")

		return report
	}

	tests := map[string]struct {
		report   *unstructured.Unstructured
		workload Workload
	}{
		"replicaset of a deployment": {loadFixture(t, "vulnerabilityreport_replicaset.json"), Workload{"deployment", "test-go-app"}},
		"exposed secret report":      {loadFixture(t, "exposedsecretreport_replicaset.json"), Workload{"deployment", "test-go-app"}},
		"statefulset":                {loadFixture(t, "vulnerabilityreport_fullref_tag.json"), Workload{"statefulset", "defectdojo-valkey"}},
		"job of a cronjob":           {loadFixture(t, "vulnerabilityreport_replicaset.json"), Workload{"cronjob", "nightly"}},
		"no namespace label":         {withoutNamespaceLabel(), Workload{"deployment", "test-go-app"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sent := &unstructured.Unstructured{Object: Payload(tt.report, tt.workload)}

			assert.Equal(t, parserService(sent.GetLabels()), Service(tt.report, tt.workload))
			assert.NotContains(t, Service(tt.report, tt.workload), "//", "no part of the service is empty")
		})
	}
}

func withoutKey(m map[string]string, key string) map[string]string {
	out := map[string]string{}

	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}

	return out
}

func TestBrokenLabels(t *testing.T) {
	for name, tc := range map[string]struct {
		labels      map[string]string
		annotations map[string]string
		want        string
	}{
		"whole": {
			labels: map[string]string{LabelResourceKind: "ReplicaSet", LabelResourceName: "web-1", LabelContainerName: "app"},
		},
		"resource name in the annotation": {
			labels:      map[string]string{LabelResourceKind: "ReplicaSet", LabelContainerName: "app"},
			annotations: map[string]string{LabelResourceName: "web-1"},
		},
		"no resource kind": {
			labels: map[string]string{LabelResourceName: "web-1", LabelContainerName: "app"},
			want:   "no resource kind or name",
		},
		"no resource name": {
			labels: map[string]string{LabelResourceKind: "ReplicaSet", LabelContainerName: "app"},
			want:   "no resource kind or name",
		},
		"no container name": {
			labels: map[string]string{LabelResourceKind: "ReplicaSet", LabelResourceName: "web-1"},
			want:   "no container name",
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels, Annotations: tc.annotations}}

			assert.Equal(t, tc.want, BrokenLabels(report))
		})
	}
}

func TestBrokenBody(t *testing.T) {
	without := func(fixture string, fields ...string) *unstructured.Unstructured {
		report := loadFixture(t, fixture)
		unstructured.RemoveNestedField(report.Object, fields...)

		return report
	}

	for name, tc := range map[string]struct {
		kind   string
		report *unstructured.Unstructured
		want   string
	}{
		"vulnerability report": {
			kind: KindVulnerabilityReport, report: loadFixture(t, "vulnerabilityreport_replicaset.json"),
		},
		"exposed secret report": {
			kind: KindExposedSecretReport, report: loadFixture(t, "exposedsecretreport_replicaset.json"),
		},
		"no report block": {
			kind: KindVulnerabilityReport, report: without("vulnerabilityreport_replicaset.json", "report"),
			want: "no report block",
		},
		"no vulnerabilities": {
			kind:   KindVulnerabilityReport,
			report: without("vulnerabilityreport_replicaset.json", "report", "vulnerabilities"),
			want:   "no report.vulnerabilities list",
		},
		"no secrets": {
			kind: KindExposedSecretReport, report: without("exposedsecretreport_replicaset.json", "report", "secrets"),
			want: "no report.secrets list",
		},
		"the kind names the list, not the object": {
			kind: KindExposedSecretReport, report: loadFixture(t, "vulnerabilityreport_replicaset.json"),
			want: "no report.secrets list",
		},
		"labels are not read": {
			kind: KindVulnerabilityReport, report: without("vulnerabilityreport_replicaset.json", "metadata", "labels"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, BrokenBody(tc.kind, tc.report))
		})
	}
}

func TestNewReimport_ReadsTheKindAndTheMetadataOnly(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	metadata := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Namespace: report.GetNamespace(), Labels: report.GetLabels(), Annotations: report.GetAnnotations(),
	}}
	image := Image{Name: "registry.example.com/app", Tag: "1.0"}

	got := NewReimport(testTarget(), KindExposedSecretReport, metadata, Workload{"deployment", "test-go-app"}, "", image)

	assert.Equal(t, Reimport{
		Product:    "in-cluster/krci-demo-dev",
		Engagement: "trivy-operator",
		TestTitle:  "ExposedSecretReport deployment/test-go-app/test-go-app",
		Service:    "krci-demo-dev/Deployment/test-go-app/test-go-app",
		Version:    "1.0",
		Tags: []string{
			"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev",
			"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app", "oci-image:registry.example.com/app",
			"report-kind:exposedsecretreport",
		},
	}, got)
}

func TestReportGVK(t *testing.T) {
	gvk := ReportGVK(KindExposedSecretReport)

	assert.Equal(t, "aquasecurity.github.io", gvk.Group)
	assert.Equal(t, "v1alpha1", gvk.Version)
	assert.Equal(t, "ExposedSecretReport", gvk.Kind)
}

func TestImportTitle(t *testing.T) {
	assert.Equal(t, "VulnerabilityReport deployment/app/web",
		TestTitle("VulnerabilityReport", Workload{"deployment", "app"}, "web"))
	assert.Equal(t, "ExposedSecretReport cronjob/nightly/job",
		TestTitle("ExposedSecretReport", Workload{"cronjob", "nightly"}, "job"))
}

func TestReportTitle_IsTheTitleOfTheImport(t *testing.T) {
	workload := Workload{"deployment", "test-go-app"}

	for _, fixture := range []string{"vulnerabilityreport_replicaset.json", "exposedsecretreport_replicaset.json"} {
		report := loadFixture(t, fixture)

		assert.Equal(t, newReimport(testTarget(), report, workload, "go-app").TestTitle, ReportTitle(report.GetKind(), report, workload))
	}
}

func TestTitleKind(t *testing.T) {
	w := Workload{"deployment", "app"}

	for _, kind := range ReportKinds {
		assert.Equal(t, kind, TitleKind(TestTitle(kind, w, "web")))
	}

	assert.Equal(t, "Trivy", TitleKind("Trivy Scan"), "a title written elsewhere yields its first word")
	assert.Empty(t, TitleKind(""))
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

func TestExpiredReport(t *testing.T) {
	tests := map[string]struct {
		annotations map[string]string
		want        bool
	}{
		"no annotation":      {annotations: nil, want: false},
		"0s":                 {annotations: map[string]string{AnnotationReportTTL: "0s"}, want: true},
		"zero in hours":      {annotations: map[string]string{AnnotationReportTTL: "0h0m0s"}, want: true},
		"168h":               {annotations: map[string]string{AnnotationReportTTL: "168h0m0s"}, want: false},
		"not a duration":     {annotations: map[string]string{AnnotationReportTTL: "never"}, want: false},
		"another annotation": {annotations: map[string]string{"other": "0s"}, want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			report := &unstructured.Unstructured{Object: map[string]any{}}
			report.SetAnnotations(tt.annotations)

			assert.Equal(t, tt.want, ExpiredReport(report))
		})
	}
}
