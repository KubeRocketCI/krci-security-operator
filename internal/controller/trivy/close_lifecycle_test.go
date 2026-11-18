package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

func TestReconcile_RemovedContainerClosesItsTestAndKeepsTheOthers(t *testing.T) {
	for name, kind := range kindsOfWorkload() {
		t.Run(name, func(t *testing.T) {
			objects := kind.objects("web", appContainer, sidecarContainer)
			reports := []*unstructured.Unstructured{
				kind.report(t, "web", appContainer), kind.report(t, "web", sidecarContainer),
			}

			h := newHarness(t, withReports(append(base(), objects...), reports...))

			h.reconcile()
			require.NotZero(t, h.activeFindingsOf(kind.title("web", appContainer)))
			require.NotZero(t, h.activeFindingsOf(kind.title("web", sidecarContainer)))

			// The sidecar leaves the pod template; Trivy Operator keeps its report.
			h.update(kind.objects("web", appContainer)[0])

			h.reconcile()

			assert.NotZero(t, h.activeFindingsOf(kind.title("web", appContainer)), "the other container is unchanged")
			assert.Zero(t, h.activeFindingsOf(kind.title("web", sidecarContainer)), "the removed container is closed")
			assert.Len(t, h.dd.reimports, 2, "the report of the removed container is not uploaded again")

			h.reconcile()
			assert.Len(t, h.dd.closed, 1, "the test is closed once")
		})
	}
}

func TestReconcile_InitContainerKeepsItsTestOpen(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]

	web := deployment("web", "1", appContainer)
	web.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "migrate"}}

	objects := append(base(), web, replicaSet(replicaSetName("web"), "web", "1"))
	h := newHarness(t, withReports(objects, deployments.report(t, "web", appContainer), deployments.report(t, "web", "migrate")))

	h.reconcile()
	h.reconcile()

	assert.NotZero(t, h.activeFindingsOf(deployments.title("web", "migrate")), "the test of an init container stays open")
	assert.NotZero(t, h.activeFindingsOf(deployments.title("web", appContainer)))
	assert.Empty(t, h.dd.closed)
	assert.Len(t, h.dd.reimports, 2)
}

func TestReconcile_DeletedWorkloadClosesItsTestsAndACreatedOneReactivatesThem(t *testing.T) {
	for name, kind := range kindsOfWorkload() {
		t.Run(name, func(t *testing.T) {
			objects := kind.objects("web", appContainer)
			h := newHarness(t, withReports(append(base(), objects...), kind.report(t, "web", appContainer)))

			h.reconcile()

			title := kind.title("web", appContainer)
			require.Equal(t, 2, h.activeFindingsOf(title))

			testID := h.dd.testIDs()[0]
			findings := h.dd.findingsIn(testID)

			for _, obj := range objects {
				h.remove(obj)
			}

			h.reconcile()

			assert.Zero(t, h.activeFindingsOf(title), "the tests of a deleted workload are closed")
			assert.Equal(t, []int{testID}, h.dd.testIDs(), "the test stays")

			for _, obj := range kind.objects("web", appContainer) {
				h.create(obj)
			}

			h.reconcile()

			assert.Equal(t, 2, h.activeFindingsOf(title), "the same report reactivates the findings")
			assert.Equal(t, []int{testID}, h.dd.testIDs())

			reactivated := h.dd.findingsIn(testID)
			require.Len(t, reactivated, len(findings))

			for i := range findings {
				assert.Equal(t, findings[i].id, reactivated[i].id, "the findings are the same")
			}
		})
	}
}

func TestReconcile_WorkloadScaledToZeroIsNotGone(t *testing.T) {
	zero := int32(0)

	standalone := replicaSet("standalone", "", "1")
	standalone.OwnerReferences = nil
	standalone.Spec.Replicas = &zero
	standalone.Spec.Template = podTemplate(appContainer)

	asleep := deployment("asleep", "1", appContainer)
	asleep.Spec.Replicas = &zero

	rs := replicaSet("asleep-rs", "asleep", "1")
	rs.Spec.Replicas = &zero

	standaloneReport := kindOfWorkload{resourceKind: "ReplicaSet", resource: ownName}.report(t, "standalone", appContainer)
	asleepReport := kindsOfWorkload()["Deployment"].report(t, "asleep", appContainer)

	h := newHarness(t, withReports(append(base(), standalone, asleep, rs), standaloneReport, asleepReport))

	const (
		standaloneTitle = "VulnerabilityReport replicaset/standalone/app"
		asleepTitle     = "VulnerabilityReport deployment/asleep/app"
	)

	h.reconcile()
	h.reconcile()

	require.NotZero(t, h.activeFindingsOf(standaloneTitle), "the report of a ReplicaSet scaled to zero is imported")
	assert.NotZero(t, h.activeFindingsOf(asleepTitle))
	assert.Empty(t, h.dd.closed)

	h.remove(standalone)
	h.reconcile()

	assert.Zero(t, h.activeFindingsOf(standaloneTitle), "deleting the ReplicaSet closes its test")
	assert.NotZero(t, h.activeFindingsOf(asleepTitle), "the Deployment scaled to zero stays")
}

func TestReconcile_FailedUploadDoesNotStopTheOtherCloseRules(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]
	other := deployments.objects("other", appContainer)

	objects := append(base(), deployments.objects("web", appContainer)...)
	objects = append(objects, other...)

	h := newHarness(t, withReports(objects, deployments.report(t, "web", appContainer), deployments.report(t, "other", appContainer)))

	h.reconcile()

	webTitle, otherTitle := deployments.title("web", appContainer), deployments.title("other", appContainer)
	require.NotZero(t, h.activeFindingsOf(webTitle))
	require.NotZero(t, h.activeFindingsOf(otherTitle))

	// The report of web changes and its upload fails; the Deployment other is deleted in the same pass.
	changed := deployments.report(t, "web", appContainer)
	changed.SetResourceVersion("")
	h.setReport(changed)

	for _, obj := range other {
		h.remove(obj)
	}

	h.dd.reimportErr = func(r defectdojo.ReimportRequest) error {
		if r.TestTitle == webTitle {
			return &defectdojo.APIError{StatusCode: 500}
		}

		return nil
	}

	_, err := h.reconcileLoggedErr()

	require.Error(t, err, "the failed upload is returned, so the workqueue retries it")
	assert.NotZero(t, h.activeFindingsOf(webTitle), "the operator does not close the test of the failed upload")
	assert.Zero(t, h.activeFindingsOf(otherTitle), "the test of the deleted workload is closed in the same pass")

	h.dd.reimportErr = nil

	h.reconcile()

	assert.NotZero(t, h.activeFindingsOf(webTitle))
	assert.Equal(t, 3, h.uploadsOf(webTitle), "the upload is tried again in the next pass")
}

func TestReconcile_ReportMarkedWithAZeroTTLIsNotImported(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]

	expiring := deployments.report(t, "web", appContainer)
	expiring.SetAnnotations(map[string]string{trivy.AnnotationReportTTL: "0s"})

	h := newHarness(t, withReports(append(base(), deployments.objects("web", appContainer)...), expiring))

	h.reconcile()

	assert.Empty(t, h.dd.reimports)

	expiring.SetAnnotations(map[string]string{trivy.AnnotationReportTTL: "24h0m0s"})
	h.setReport(expiring)

	h.reconcile()

	assert.Len(t, h.dd.reimports, 1, "a report with a TTL that is not 0s is imported")
}

func TestReconcile_ReportOfAnOldReplicaSetIsNotImportedAndItsTestStaysOpen(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]

	objects := append(base(), deployments.objects("web", appContainer)...)
	objects = append(objects, replicaSet("web-old", "web", "0"))
	oldReport := kindOfWorkload{resourceKind: "ReplicaSet", resource: func(string) string { return "web-old" }}.
		report(t, "web", appContainer)

	h := newHarness(t, withReports(objects, oldReport, deployments.report(t, "web", appContainer)))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1, "only the report of the current revision is imported")
	assert.Equal(t, "replicaset-web-rs-app", reportNameOf(t, h.dd.reimports[0]))
	assert.NotZero(t, h.activeFindingsOf(deployments.title("web", appContainer)))
}

// reportNameOf is the name of the report an upload carries.
func reportNameOf(t *testing.T, r defectdojo.ReimportRequest) string {
	t.Helper()

	payload := map[string]any{}
	require.NoError(t, json.Unmarshal(r.Report, &payload))

	metadata, ok := payload["metadata"].(map[string]any)
	require.True(t, ok)

	name, ok := metadata["name"].(string)
	require.True(t, ok)

	return name
}

func TestReconcile_TwoCurrentReportsOnOneTitleGiveTheSameChoiceOnEveryPass(t *testing.T) {
	cronJobs := kindsOfWorkload()["CronJob"]

	// The CronJob has its own report, and its newest Job has one: both name the test of the CronJob.
	onCronJob := cronJobs.report(t, "nightly", appContainer)
	onJob := jobReport(t, "nightly-2")

	objects := append(base(), cronJobs.objects("nightly", appContainer)...)
	objects = append(objects, cronJob("nightly-1", time.Hour), cronJob("nightly-2", 0))

	for _, reports := range [][]*unstructured.Unstructured{{onCronJob, onJob}, {onJob, onCronJob}} {
		h := newHarness(t, withReports(objects, reports...))

		logged := h.reconcileLogged()

		require.Len(t, h.dd.reimports, 1, "one report is imported")
		assert.Equal(t, onCronJob.GetName(), reportNameOf(t, h.dd.reimports[0]), "the report on the CronJob comes first")
		assert.Contains(t, logged, "Ignored a report of a test that has another current report")
		assert.Contains(t, logged, onJob.GetName(), "the report that is not used is logged")

		h.reconcile()
		h.reconcile()

		assert.Len(t, h.dd.reimports, 1, "the choice is the same on every pass")
		assert.Empty(t, h.dd.closed, "the test of a live CronJob stays open")
	}
}

// descendingReports lists the reports of the Trivy Operator group in descending name order.
func descendingReports() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}

			if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Group == trivy.TrivyGroup {
				slices.Reverse(u.Items)
			}

			return nil
		},
	}
}

func TestReconcile_ReportThatLosesTheChoiceIsNotUploadedWhateverTheListOrder(t *testing.T) {
	jobs := jobReport(t, "nightly-2")
	onReplicaSet := kindsOfWorkload()["Deployment"].report(t, "web", appContainer)

	for name, tc := range map[string]struct {
		objects []client.Object
		own     *unstructured.Unstructured
		other   *unstructured.Unstructured
	}{
		"CronJob and its newest Job": {
			objects: append(kindsOfWorkload()["CronJob"].objects("nightly", appContainer), cronJob("nightly-1", time.Hour), cronJob("nightly-2", 0)),
			own:     kindsOfWorkload()["CronJob"].report(t, "nightly", appContainer),
			other:   jobs,
		},
		"Deployment and its current ReplicaSet": {
			objects: kindsOfWorkload()["Deployment"].objects("web", appContainer),
			own:     kindOfWorkload{resourceKind: "Deployment", resource: ownName}.report(t, "web", appContainer),
			other:   onReplicaSet,
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The list runs in descending name order: the report that loses comes first.
			require.Greater(t, tc.other.GetName(), tc.own.GetName())

			h := newHarness(t, withReports(append(base(), tc.objects...), tc.other, tc.own), descendingReports())

			logged := h.reconcileLogged()

			require.Len(t, h.dd.reimports, 1, "the report that loses is not uploaded before the winner")
			assert.Equal(t, tc.own.GetName(), reportNameOf(t, h.dd.reimports[0]))
			assert.Contains(t, logged, "Ignored a report of a test that has another current report")
			assert.Contains(t, logged, tc.other.GetName())

			h.reconcile()
			h.reconcile()

			assert.Len(t, h.dd.reimports, 1, "no pass uploads the report that loses")
		})
	}
}

func TestReconcile_ReportOfAReplicaSetIsUploadedWhenTheDeploymentHasNoCurrentReport(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]
	objects := append(base(), deployments.objects("web", appContainer)...)

	onReplicaSet := deployments.report(t, "web", appContainer)
	expiring := kindOfWorkload{resourceKind: "Deployment", resource: ownName}.report(t, "web", appContainer)
	expiring.SetAnnotations(map[string]string{trivy.AnnotationReportTTL: "0s"})

	for name, reports := range map[string][]*unstructured.Unstructured{
		"no report on the Deployment":      {onReplicaSet},
		"report of the Deployment expires": {onReplicaSet, expiring},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(objects, reports...))

			h.reconcile()

			require.Len(t, h.dd.reimports, 1)
			assert.Equal(t, onReplicaSet.GetName(), reportNameOf(t, h.dd.reimports[0]))
		})
	}
}

func TestReconcile_TwoCurrentReportsOfOneKindAreChosenByName(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]

	first := deployments.report(t, "web", appContainer)
	first.SetName("a-report")

	second := deployments.report(t, "web", appContainer)
	second.SetName("b-report")
	second.SetUID("uid-b")

	h := newHarness(t, withReports(append(base(), deployments.objects("web", appContainer)...), second, first))

	logged := h.reconcileLogged()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, "a-report", reportNameOf(t, h.dd.reimports[0]))
	assert.Contains(t, logged, "b-report")
}

func TestReconcile_TestsOfEveryWorkloadKindAreExpected(t *testing.T) {
	// Bare Pods and Jobs, ReplicaSets without a Deployment and every other kind keep their tests while they exist.
	objects := append(base(),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: appNS}, Spec: podTemplate(appContainer).Spec},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-abc", Namespace: appNS, OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", Controller: ptr.To(true)},
			}},
			Spec: podTemplate(appContainer).Spec,
		},
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "migrate", Namespace: appNS},
			Spec:       batchv1.JobSpec{Template: podTemplate(appContainer)},
		},
	)

	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "CronJob"} {
		objects = append(objects, kindsOfWorkload()[kind].objects("web", appContainer)...)
	}

	h := newHarness(t, objects)

	titles := []string{
		"deployment/web/app", "statefulset/web/app", "daemonset/web/app", "cronjob/web/app", "pod/debug/app", "job/migrate/app",
	}

	id := 10

	for _, title := range titles {
		for _, kind := range []string{trivy.KindVulnerabilityReport, trivy.KindExposedSecretReport} {
			h.dd.seedTests(ownedTest(id, kind+" "+title))

			id++
		}
	}

	// Pods of a controller and the Jobs of a CronJob are not workloads of their own.
	h.dd.seedTests(ownedTest(id, "VulnerabilityReport pod/web-abc/app"), ownedTest(id+1, "VulnerabilityReport job/nightly-1/app"))

	h.reconcile()

	assert.Equal(t, []int{id, id + 1}, h.dd.closed, "only the tests of no workload are closed")
}

func TestReconcile_ReportKindsOfOneWorkloadAreClosedTogether(t *testing.T) {
	objects := goAppObjects()
	h := newHarness(t, withReports(objects, goApp(t), goAppSecrets(t)))

	h.reconcile()

	require.NotZero(t, h.activeFindingsOf(goAppTitle))
	require.NotZero(t, h.activeFindingsOf(secretsTitle))

	h.remove(objects[goAppDeployment])
	h.remove(objects[goAppDeployment+1])

	h.reconcile()

	assert.Zero(t, h.activeFindingsOf(goAppTitle))
	assert.Zero(t, h.activeFindingsOf(secretsTitle))
}

func TestReconcile_WorkloadCreatedAfterTheImportSnapshotKeepsItsTest(t *testing.T) {
	// The Deployment web is created again (Argo CD replace, helm reinstall) after the pass listed the Deployments
	// for the first report and before it decides what to close.
	created := false

	recreated := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			err := c.List(ctx, list, opts...)

			if _, ok := list.(*appsv1.DeploymentList); ok && err == nil && !created {
				created = true

				return c.Create(ctx, deployment("web", "1", appContainer))
			}

			return err
		},
	}

	h := newHarness(t, withReports(goAppObjects(), goApp(t)), recreated)
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport deployment/web/app"), ownedTest(8, "VulnerabilityReport deployment/gone/app"))

	h.reconcile()

	require.True(t, created)
	assert.Equal(t, []int{8}, h.dd.closed, "the test of the workload that exists at the close is not closed")
}

func TestReconcile_ListFailureOfWorkloadsClosesNothing(t *testing.T) {
	failing := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*appsv1.StatefulSetList); ok {
				return errors.New("forbidden")
			}

			return c.List(ctx, list, opts...)
		},
	}

	h := newHarness(t, goAppObjects(), failing)
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport deployment/removed/removed"))

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.closed, "workloads that cannot be listed are not workloads that are gone")
}
