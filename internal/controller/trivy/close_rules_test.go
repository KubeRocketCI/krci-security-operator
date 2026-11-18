package trivy

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	appContainer     = "app"
	sidecarContainer = "sidecar"
)

// reconcileLoggedErr reconciles the namespace of the app and returns the error and what the pass logged.
func (h *harness) reconcileLoggedErr() (string, error) {
	h.t.Helper()

	var lines []string

	log := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})

	_, err := h.reconciler.Reconcile(ctrl.LoggerInto(context.Background(), log), namespaceRequest(appNS))

	return strings.Join(lines, "\n"), err
}

// update replaces the stored workload with obj.
func (h *harness) update(obj client.Object) {
	h.t.Helper()

	existing := obj.DeepCopyObject().(client.Object) //nolint:forcetypeassert // DeepCopyObject keeps the type

	require.NoError(h.t, h.client.Get(context.Background(), client.ObjectKeyFromObject(obj), existing))
	obj.SetResourceVersion(existing.GetResourceVersion())
	require.NoError(h.t, h.client.Update(context.Background(), obj))
}

// kindOfWorkload is a workload kind of the cluster: the objects it consists of and the resource its reports name.
type kindOfWorkload struct {
	// kind is the kind as it appears in test titles and tags.
	kind string
	// resourceKind is the kind of the resource its reports name.
	resourceKind string
	// objects are the Kubernetes objects of the workload with the containers.
	objects func(name string, containers ...string) []client.Object
	// resource is the name of the resource its reports name.
	resource func(name string) string
}

func ownName(name string) string { return name }

func replicaSetName(name string) string { return name + "-rs" }

func kindsOfWorkload() map[string]kindOfWorkload {
	return map[string]kindOfWorkload{
		"Deployment": {
			kind:         "deployment",
			resourceKind: "ReplicaSet",
			objects: func(name string, containers ...string) []client.Object {
				return []client.Object{deployment(name, "1", containers...), replicaSet(replicaSetName(name), name, "1")}
			},
			resource: replicaSetName,
		},
		"StatefulSet": {
			kind:         "statefulset",
			resourceKind: "StatefulSet",
			objects: func(name string, containers ...string) []client.Object {
				return []client.Object{&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: appNS},
					Spec:       appsv1.StatefulSetSpec{Template: podTemplate(containers...)},
				}}
			},
			resource: ownName,
		},
		"DaemonSet": {
			kind:         "daemonset",
			resourceKind: "DaemonSet",
			objects: func(name string, containers ...string) []client.Object {
				return []client.Object{&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: appNS},
					Spec:       appsv1.DaemonSetSpec{Template: podTemplate(containers...)},
				}}
			},
			resource: ownName,
		},
		"CronJob": {
			kind:         "cronjob",
			resourceKind: "CronJob",
			objects: func(name string, containers ...string) []client.Object {
				return []client.Object{&batchv1.CronJob{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: appNS},
					Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{
						Spec: batchv1.JobSpec{Template: podTemplate(containers...)},
					}},
				}}
			},
			resource: ownName,
		},
		"Job": {
			kind:         "job",
			resourceKind: "Job",
			objects: func(name string, containers ...string) []client.Object {
				return []client.Object{&batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: appNS},
					Spec:       batchv1.JobSpec{Template: podTemplate(containers...)},
				}}
			},
			resource: ownName,
		},
		"Pod": {
			kind:         "pod",
			resourceKind: "Pod",
			objects: func(name string, containers ...string) []client.Object {
				return []client.Object{&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: appNS},
					Spec:       podTemplate(containers...).Spec,
				}}
			},
			resource: ownName,
		},
		"ReplicaSet": {
			kind:         "replicaset",
			resourceKind: "ReplicaSet",
			objects: func(name string, containers ...string) []client.Object {
				rs := replicaSet(name, "", "1")
				rs.OwnerReferences = nil
				rs.Spec.Template = podTemplate(containers...)

				return []client.Object{rs}
			},
			resource: ownName,
		},
	}
}

// report is the VulnerabilityReport of a container of the workload of the kind.
func (k kindOfWorkload) report(t *testing.T, name, container string) *unstructured.Unstructured {
	t.Helper()

	r := goApp(t)
	r.SetName(strings.ToLower(k.resourceKind + "-" + k.resource(name) + "-" + container))
	r.SetUID(types.UID("uid-" + r.GetName()))
	r.SetLabels(map[string]string{
		trivy.LabelResourceKind:      k.resourceKind,
		trivy.LabelResourceName:      k.resource(name),
		trivy.LabelResourceNamespace: appNS,
		trivy.LabelContainerName:     container,
	})

	return r
}

// title is the title of the test of a container of the workload.
func (k kindOfWorkload) title(name, container string) string {
	return "VulnerabilityReport " + k.kind + "/" + name + "/" + container
}

// base are the objects every namespace of these tests has.
func base() []client.Object {
	return []client.Object{integrationSecret(), namespaceObject(appNS, nil)}
}

func TestReconcile_MissingReportDoesNotCloseTheTestOfARunningWorkload(t *testing.T) {
	// A report is missing after the TTL of Trivy Operator expired, for an image Trivy Operator excludes, and after
	// a scan that failed.
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()
	require.Equal(t, 2, h.activeFindingsOf(goAppTitle))

	h.deleteReport(goApp(t))

	h.reconcile()
	h.reconcile()

	assert.Empty(t, h.dd.closed, "a missing report closes nothing")
	assert.Equal(t, 2, h.activeFindingsOf(goAppTitle))
}

func TestReconcile_ReportDeletedAndWrittenAgainLeavesEveryFindingActive(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))

	h.reconcile()

	before := h.dd.findingsIn(h.dd.testIDs()[0])
	require.Len(t, before, 2)

	h.deleteReport(goApp(t))
	h.reconcile()

	assert.Equal(t, before, h.dd.findingsIn(h.dd.testIDs()[0]), "the gap of the rescan changes no finding")

	h.setReport(goApp(t))
	h.reconcile()

	assert.Equal(t, before, h.dd.findingsIn(h.dd.testIDs()[0]), "the new report keeps every finding as it was")
	assert.Empty(t, h.dd.closed, "no close in between")
}

func TestReconcile_ExcludedImageKeepsItsTestOpen(t *testing.T) {
	// Trivy Operator writes no report for the image; the test of an earlier scan stays as it is.
	h := newHarness(t, goAppObjects())
	h.dd.seedTests(ownedTest(7, goAppTitle))
	h.dd.seedFinding(7, "CVE-2026-1", goAppService)

	h.reconcile()

	assert.Empty(t, h.dd.closed)
	assert.Equal(t, 1, h.activeFindingsOf(goAppTitle))
}
