package trivy

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// restart replaces the reconciler by a new one over the same cluster and DefectDojo: no in-memory state is kept.
func (h *harness) restart() {
	h.t.Helper()

	r := NewReconciler(h.reconciler.cache, h.reconciler.reader, h.reconciler.config, h.reconciler.watched,
		func(string, string) DefectDojo { return h.dd })
	r.now, r.random = h.reconciler.now, h.reconciler.random
	h.reconciler = r
}

// markerOf returns the build_id of the test.
func (h *harness) markerOf(testID int) string { return h.dd.test(testID).buildID }

func TestReconcile_UploadMarkerIsTheBuildIDOfTheTest(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()

	marker := h.markerOf(testID)

	assert.Regexp(t, `^uid-vulnerabilityreport_replicaset\.json:[0-9]+:[0-9a-f]{12}$`, marker)
	assert.LessOrEqual(t, len(marker), 100)
}

func TestReconcile_UploadMarkerOfANewTestIsSetAfterTheReimport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()

	assert.Empty(t, h.dd.reimports[0].BuildID, "DefectDojo saves the build_id of a new test before it reads the report")
	assert.NotEmpty(t, h.markerOf(testID))
	assert.Equal(t, 1, h.dd.buildIDUpdates)
}

func TestReconcile_UploadMarkerOfAnExistingTestGoesWithTheReimport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()
	before := h.markerOf(testID)

	changed := goApp(t)
	changed.SetResourceVersion("")
	h.setReport(changed)

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.NotEmpty(t, h.dd.reimports[1].BuildID, "the test of an earlier reimport in this process exists")
	assert.Equal(t, h.dd.reimports[1].BuildID, h.markerOf(testID))
	assert.NotEqual(t, before, h.markerOf(testID))
	assert.Equal(t, 1, h.dd.buildIDUpdates, "no update after the reimport")
}

func TestReconcile_AfterARestartAnExistingTestGetsTheMarkerWithTheReimport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.seedTests(defectdojo.Test{ID: 7, Title: goAppTitle})

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.NotEmpty(t, h.dd.reimports[0].BuildID, "the tests read shows the test")
	assert.Equal(t, h.dd.reimports[0].BuildID, h.markerOf(7))
	assert.Zero(t, h.dd.buildIDUpdates)
}

func TestReconcile_FirstImportThatFailsAfterTheTestWasCreatedIsUploadedAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		rejected bool
	}{
		"server error": {status: 500},
		"rejected":     {status: 400, rejected: true},
	} {
		t.Run(name, func(t *testing.T) {
			rejectedBefore := testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport))

			h := newHarness(t, withReports(goAppObjects(), goApp(t)))
			h.dd.reimportAfterTestErr = func(defectdojo.ReimportRequest) error {
				return &defectdojo.APIError{StatusCode: tc.status}
			}

			var lines []string

			log := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})
			ctx := ctrl.LoggerInto(context.Background(), log)

			pass := func() error {
				_, err := h.reconciler.Reconcile(ctx, namespaceRequest(appNS))

				return err
			}

			if tc.rejected {
				require.NoError(t, pass())
			} else {
				require.Error(t, pass())
			}

			require.Len(t, h.dd.reimports, 1)
			require.Len(t, h.dd.testIDs(), 1, "DefectDojo created the test before the failure")

			testID := h.dd.testIDs()[0]

			assert.Empty(t, h.markerOf(testID), "the report is not marked as uploaded")

			h.restart()

			if tc.rejected {
				require.NoError(t, pass())
			} else {
				require.Error(t, pass())
			}

			require.Len(t, h.dd.reimports, 2, "the report is uploaded again after a restart")
			assert.NotEmpty(t, h.dd.reimports[1].BuildID, "the tests read shows the test: the marker goes with the reimport")
			assert.Empty(t, h.markerOf(testID))

			rejections := 0

			for _, line := range lines {
				if strings.Contains(line, "DefectDojo rejected a report version") {
					rejections++
				}
			}

			if tc.rejected {
				assert.Equal(t, 2, rejections, "the rejection is logged again after a restart")
				assert.InDelta(t, rejectedBefore+2,
					testutil.ToFloat64(rejectedReports.WithLabelValues(trivy.KindVulnerabilityReport)), 0)
			} else {
				assert.Zero(t, rejections)
			}

			h.dd.reimportAfterTestErr = nil
			h.restart()

			require.NoError(t, pass())
			require.Len(t, h.dd.reimports, 3)
			assert.NotEmpty(t, h.markerOf(testID))
			assert.Len(t, h.dd.findingsIn(testID), 2)

			h.restart()
			require.NoError(t, pass())
			assert.Len(t, h.dd.reimports, 3, "the completed upload is skipped after a restart")
		})
	}
}

func TestReconcile_FirstImportThatFailsAfterTheTestWasCreatedIsUploadedAgainInTheNextPass(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.reimportAfterTestErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 500} }

	require.Error(t, h.reconcileErr())

	h.dd.reimportAfterTestErr = nil
	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.NotEmpty(t, h.markerOf(h.dd.testIDs()[0]))
}

func TestReconcile_FirstImportWhoseMarkerUpdateFailsIsUploadedAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.buildIDErr = &defectdojo.APIError{StatusCode: 502}

	require.Error(t, h.reconcileErr())

	testID := h.dd.testIDs()[0]

	assert.Len(t, h.dd.findingsIn(testID), 2, "the reimport completed")
	assert.Empty(t, h.markerOf(testID))

	h.dd.buildIDErr = nil
	h.restart()
	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "a test without marker is not known to hold the report")
	assert.NotEmpty(t, h.markerOf(testID))

	h.restart()
	h.reconcile()

	assert.Len(t, h.dd.reimports, 2)
}

func TestReconcile_AfterARestartAnUnchangedReportIsNotUploadedAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	h.reconcile()

	require.Len(t, h.dd.reimports, 2)

	findings := map[int][]ddFinding{}
	for _, id := range h.dd.testIDs() {
		findings[id] = h.dd.findingsIn(id)
	}

	h.restart()
	h.dd.testReads = 0

	h.reconcile()

	assert.Len(t, h.dd.reimports, 2, "the tests already hold the marker of each report")
	assert.Equal(t, 1, h.dd.testReads, "the tests are read once, for the markers and for the close rules")
	assert.Empty(t, h.dd.closed)

	for id, want := range findings {
		assert.Equal(t, want, h.dd.findingsIn(id))
	}

	h.dd.testReads = 0

	h.reconcile()

	assert.Len(t, h.dd.reimports, 2)
	assert.Equal(t, 1, h.dd.testReads, "a skipped report is remembered: the next pass reads the tests for the close rules only")
}

func TestReconcile_AfterARestartAChangedReportIsUploaded(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()
	before := h.markerOf(testID)

	h.restart()

	changed := goApp(t)
	changed.SetResourceVersion("")
	h.setReport(changed)

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.NotEqual(t, before, h.markerOf(testID))
}

func TestReconcile_AfterARestartATestWithAnotherOrNoMarkerIsUploaded(t *testing.T) {
	for name, marker := range map[string]string{
		"no marker":      "",
		"another marker": "uid-other:7:0123456789ab",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), goApp(t)))
			h.dd.seedTests(defectdojo.Test{ID: 7, Title: goAppTitle, BuildID: marker})

			h.reconcile()

			require.Len(t, h.dd.reimports, 1)
			assert.Equal(t, []int{7}, h.dd.testIDs(), "the report goes into the existing test")
			assert.Equal(t, h.dd.reimports[0].BuildID, h.markerOf(7))
			assert.Len(t, h.dd.findingsIn(7), 2)
		})
	}
}

func TestReconcile_TestUploadedBeforeTheReportKindTagIsUploadedOnceAndCarriesTheTag(t *testing.T) {
	// The tags of a test and the marker of its report as the operator wrote them before the report-kind tag.
	beforeTags := []string{
		"k8s-cluster:in-cluster", "k8s-namespace:krci-demo-dev", "k8s-workload:deployment.test-go-app",
		"k8s-container:test-go-app", "oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app",
	}

	for name, tc := range map[string]struct {
		report       func(*testing.T) *unstructured.Unstructured
		title        string
		beforeMarker string
		kindTag      string
	}{
		"vulnerability report": {
			report: goApp, title: goAppTitle,
			beforeMarker: "uid-vulnerabilityreport_replicaset.json:100:0180cbf87179", kindTag: "report-kind:vulnerabilityreport",
		},
		"exposed secret report": {
			report: goAppSecrets, title: secretsTitle,
			beforeMarker: "uid-exposedsecretreport_replicaset.json:100:a90a13383437", kindTag: "report-kind:exposedsecretreport",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), tc.report(t)))
			h.dd.seedTests(defectdojo.Test{ID: 7, Title: tc.title, BuildID: tc.beforeMarker, Tags: beforeTags})

			h.reconcile()

			require.Len(t, h.dd.reimports, 1, "the tag is part of the request: the marker of the test is not the one of the report")
			assert.Equal(t, []int{7}, h.dd.testIDs(), "the report goes into the existing test")
			assert.ElementsMatch(t, append(slices.Clone(beforeTags), tc.kindTag), h.dd.test(7).tags)
			assert.Equal(t, h.dd.reimports[0].BuildID, h.markerOf(7))
			assert.NotEqual(t, tc.beforeMarker, h.markerOf(7))

			h.reconcile()
			h.restart()
			h.reconcile()

			assert.Len(t, h.dd.reimports, 1, "the second pass and the first pass after a restart upload nothing")
		})
	}
}

func TestReconcile_AfterARestartAReportWhoseUploadWasRejectedIsUploadedAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()
	before := h.markerOf(testID)

	changed := goApp(t)
	changed.SetResourceVersion("")
	h.setReport(changed)

	h.dd.reimportErr = rejectGoApp

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, before, h.markerOf(testID), "a rejected upload leaves the marker of the earlier upload")

	h.restart()
	h.dd.reimportErr = nil

	h.reconcile()

	require.Len(t, h.dd.reimports, 3, "the rejection is not remembered across a restart")
	assert.NotEqual(t, before, h.markerOf(testID))
}

func TestReconcile_AfterARestartAReportWhoseRequestChangedIsUploaded(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()
	before := h.markerOf(testID)

	h.restart()

	dep := &appsv1.Deployment{}
	require.NoError(t, h.client.Get(context.Background(), client.ObjectKey{Namespace: appNS, Name: "test-go-app"}, dep))
	dep.SetLabels(map[string]string{"argocd.argoproj.io/instance": "legacy"})
	require.NoError(t, h.client.Update(context.Background(), dep))

	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "the report is the same, the component tag it is sent with is not")
	assert.Contains(t, h.dd.test(testID).tags, "app:legacy")
	assert.NotEqual(t, before, h.markerOf(testID))
}

func TestReconcile_UploadMarkerIsTheSameOnEveryPassForOneReportVersion(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()
	first := h.markerOf(testID)

	h.dd.deleteAllTests()
	h.restart()
	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "DefectDojo lost the test: the report is uploaded into a new one")
	assert.Equal(t, first, h.markerOf(h.dd.testIDs()[0]))
}

func TestReconcile_AfterARestartAReadFailureOfTheTestsFailsThePassBeforeTheUploads(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	h.reconcile()
	h.restart()

	h.dd.listErr = &defectdojo.APIError{StatusCode: 502}

	require.Error(t, h.reconcileErr())
	assert.Len(t, h.dd.reimports, 2, "no report is uploaded while DefectDojo cannot tell what it holds")

	h.dd.listErr = nil
	h.reconcile()

	assert.Len(t, h.dd.reimports, 2, "the next pass finds the markers")
}

func TestReconcile_AfterARestartAMissingProductDoesNotStopTheUploads(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconcile()
	h.dd.deleteProducts()
	h.restart()

	h.reconcile()

	assert.Len(t, h.dd.reimports, 2, "the product is created by the upload")
}

func TestReconcile_ClosedTestLosesItsMarkerSoItsReportIsUploadedAgain(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()

	h.reconciler.config.ExcludeNamespaces = []string{appNS}
	h.reconcile()

	require.Equal(t, []int{testID}, h.dd.closed)
	assert.Empty(t, h.markerOf(testID))
	assert.Equal(t, map[string]string{cveKept: statusClosed, cveFixed: statusClosed}, h.dd.statuses(testID, goAppService))

	h.reconciler.config.ExcludeNamespaces = nil
	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "the unchanged report is uploaded again into the closed test")
	assert.Equal(t, map[string]string{cveKept: statusActive, cveFixed: statusActive}, h.dd.statuses(testID, goAppService))
}

func TestReconcile_StaleTestLosesItsMarkerWhenItIsClosed(t *testing.T) {
	objects := goAppObjects()

	h := newHarness(t, withReports(objects, goApp(t)))
	testID := h.onlyTest()

	h.remove(objects[goAppDeployment])
	h.remove(objects[goAppDeployment+1])
	h.reconcile()

	require.Equal(t, []int{testID}, h.dd.closed)
	assert.Empty(t, h.markerOf(testID))

	h.restart()
	h.create(deployment("test-go-app", "1"))
	h.create(replicaSet("test-go-app-9dc66c9c6", "test-go-app", "1"))

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.Equal(t, map[string]string{cveKept: statusActive, cveFixed: statusActive}, h.dd.statuses(testID, goAppService))
}

func TestReconcile_AfterARestartATestOfAnEarlierEngagementDoesNotHoldTheReport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.onlyTest()

	h.dd.addEngagement(goAppContext)
	h.restart()

	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "a reimport writes into the last engagement with the name, which has no test")
	assert.Len(t, h.dd.testIDs(), 2)
}

func TestReconcile_AChangedRequestIsUploadedWithinTheProcess(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	testID := h.onlyTest()
	before := h.markerOf(testID)

	dep := &appsv1.Deployment{}
	require.NoError(t, h.client.Get(context.Background(), client.ObjectKey{Namespace: appNS, Name: "test-go-app"}, dep))
	dep.SetLabels(map[string]string{"argocd.argoproj.io/instance": "legacy"})
	require.NoError(t, h.client.Update(context.Background(), dep))

	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "the report is the same, the component tag it is sent with is not")
	assert.Contains(t, h.dd.test(testID).tags, "app:legacy")
	assert.NotEqual(t, before, h.markerOf(testID))

	h.reconcile()

	assert.Len(t, h.dd.reimports, 2, "an unchanged request is not uploaded again")
}

func TestReconcile_ClosingAStaleTestWithoutMarkerUpdatesNothing(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport deployment/removed/removed"))

	h.reconcile()

	require.Equal(t, []int{7}, h.dd.closed)
	assert.Zero(t, h.dd.buildIDUpdates, "there is no marker to clear")
}

func TestReconcile_AfterARestartAClosedTestIsNotUpdatedAgain(t *testing.T) {
	h := newHarness(t, goAppObjects())
	h.dd.seedTests(defectdojo.Test{ID: 7, Title: "VulnerabilityReport deployment/removed/removed", BuildID: "uid:1:0123456789ab"})

	h.reconcile()

	require.Equal(t, []int{7}, h.dd.closed)
	require.Equal(t, 1, h.dd.buildIDUpdates)

	h.restart()
	h.reconcile()

	assert.Equal(t, []int{7, 7}, h.dd.closed, "the close is repeated after a restart")
	assert.Equal(t, 1, h.dd.buildIDUpdates, "the cleared build_id is not updated again")
}

func TestReconcile_TestClosedRightAfterItsUploadLosesTheMarkerOfThatUpload(t *testing.T) {
	objects := goAppObjects()

	h := newHarness(t, withReports(objects, goApp(t)))
	h.dd.seedTests(defectdojo.Test{ID: 7, Title: goAppTitle})

	h.dd.reimportAfterTestErr = func(defectdojo.ReimportRequest) error {
		h.remove(objects[goAppDeployment])
		h.remove(objects[goAppDeployment+1])

		return nil
	}

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	require.Equal(t, []int{7}, h.dd.closed, "the workload is gone by the end of the pass")
	assert.Empty(t, h.markerOf(7), "the close clears the marker the upload wrote")
}
