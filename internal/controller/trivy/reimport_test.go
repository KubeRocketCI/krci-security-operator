package trivy

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
		}, Spec: appsv1.DeploymentSpec{Template: podTemplate("test-go-app")}}

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
		"tag": {artifact: nil, want: "main-20261110-194848"},
		"report without a tag: digest of the report": {
			artifact: map[string]string{"tag": ""}, want: "sha256:9155b03ee4d9",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), withArtifact(t, tt.artifact)))
			testID := h.onlyTest()

			assert.Equal(t, tt.want, h.dd.test(testID).version)
		})
	}
}

const (
	pythonDigest = "sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317"
	newerDigest  = "sha256:1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"
)

// asDockerHubReport sets the image fields of the report as Trivy Operator writes them for a Docker Hub image: the
// whole repository with library/, the registry server index.docker.io and the artifact fields.
func asDockerHubReport(t *testing.T, report *unstructured.Unstructured, artifact map[string]string) *unstructured.Unstructured {
	t.Helper()

	require.NoError(t, unstructured.SetNestedField(report.Object, "index.docker.io", "report", "registry", "server"))

	for field, value := range artifact {
		require.NoError(t, unstructured.SetNestedField(report.Object, value, "report", "artifact", field))
	}

	return report
}

// withImage returns the objects with the image of every container of the pod templates of the workloads.
func withImage(objects []client.Object, image string) []client.Object {
	out := make([]client.Object, 0, len(objects))

	for _, o := range objects {
		o = o.DeepCopyObject().(client.Object) //nolint:forcetypeassert // DeepCopyObject keeps the type

		switch w := o.(type) {
		case *appsv1.Deployment:
			setImage(&w.Spec.Template.Spec, image)
		case *appsv1.ReplicaSet:
			setImage(&w.Spec.Template.Spec, image)
		case *appsv1.StatefulSet:
			setImage(&w.Spec.Template.Spec, image)
		case *appsv1.DaemonSet:
			setImage(&w.Spec.Template.Spec, image)
		case *batchv1.CronJob:
			setImage(&w.Spec.JobTemplate.Spec.Template.Spec, image)
		case *batchv1.Job:
			setImage(&w.Spec.Template.Spec, image)
		case *corev1.Pod:
			setImage(&w.Spec, image)
		}

		out = append(out, o)
	}

	return out
}

func setImage(spec *corev1.PodSpec, image string) {
	for i := range spec.Containers {
		spec.Containers[i].Image = image
	}
}

// imageScenario is a workload kind with the container "app" and the report of that container.
type imageScenario struct {
	objects func() []client.Object
	report  func(t *testing.T) *unstructured.Unstructured
}

func imageScenarios() map[string]imageScenario {
	out := map[string]imageScenario{}

	for name, k := range kindsOfWorkload() {
		out[name] = imageScenario{
			objects: func() []client.Object { return append(base(), k.objects("web", appContainer)...) },
			report:  func(t *testing.T) *unstructured.Unstructured { return k.report(t, "web", appContainer) },
		}
	}

	// The report of a CronJob is the report of its newest Job.
	out["CronJob"] = imageScenario{
		objects: func() []client.Object {
			return append(base(), cronJob("nightly-1", time.Hour), cronJob("nightly-2", 0),
				kindsOfWorkload()["CronJob"].objects("nightly", appContainer)[0])
		},
		report: func(t *testing.T) *unstructured.Unstructured { return jobReport(t, "nightly-2") },
	}

	return out
}

func TestReconcile_VersionOfAWorkloadKindComesFromTheReportExceptForTheBogusTagOfADigestOnlyImage(t *testing.T) {
	// Trivy Operator writes the last path segment of the repository as the tag of a digest-only image.
	digestOnly := map[string]string{"repository": "library/python", "tag": "python", "digest": pythonDigest}
	tagged := map[string]string{"repository": "library/python", "tag": "3.13", "digest": pythonDigest}

	tests := map[string]struct {
		image    string
		artifact map[string]string
		want     string
	}{
		"digest only": {
			image: "python@" + pythonDigest, artifact: digestOnly, want: "sha256:8fb099199b9f",
		},
		"private registry with a port, digest only": {
			image:    "registry.example.com:5000/krci/python@" + pythonDigest,
			artifact: map[string]string{"repository": "krci/python", "tag": "python", "digest": pythonDigest},
			want:     "sha256:8fb099199b9f",
		},
		"tag only":       {image: "python:3.13", artifact: tagged, want: "3.13"},
		"tag and digest": {image: "python:3.13@" + pythonDigest, artifact: tagged, want: "3.13"},
		"image without a tag or a digest": {
			image:    "python",
			artifact: map[string]string{"repository": "library/python", "tag": "latest", "digest": pythonDigest},
			want:     "latest",
		},
		"no image in the template": {image: "", artifact: digestOnly, want: "python"},
		"template ahead of the report, digest only: the report": {
			image: "python@" + newerDigest, artifact: digestOnly, want: "python",
		},
		"template ahead of the report, tag only: the report": {
			image: "python:3.14", artifact: tagged, want: "3.13",
		},
		"template ahead of the report, other repository: the report": {
			image: "registry.example.com/krci/python@" + newerDigest, artifact: digestOnly, want: "python",
		},
	}

	for kind, scenario := range imageScenarios() {
		for name, tt := range tests {
			t.Run(kind+"/"+name, func(t *testing.T) {
				objects := withImage(scenario.objects(), tt.image)
				report := asDockerHubReport(t, scenario.report(t), tt.artifact)

				h := newHarness(t, withReports(objects, report))
				testID := h.onlyTest()

				assert.Equal(t, tt.want, h.dd.test(testID).version)
			})
		}
	}
}

func TestReconcile_ImageTagOfTheTestComesFromTheReport(t *testing.T) {
	digestOnly := map[string]string{"repository": "library/python", "tag": "python", "digest": pythonDigest}
	report := asDockerHubReport(t, goApp(t), digestOnly)

	h := newHarness(t, withReports(withImage(goAppObjects(), "python@"+pythonDigest), report))
	testID := h.onlyTest()

	assert.Contains(t, h.dd.test(testID).tags, "oci-image:python")
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
		integrationSecret(), namespaceObject(appNS, nil), deployment(name, "1", "test-go-app"), replicaSet(replicaSetName, name, "1"),
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
