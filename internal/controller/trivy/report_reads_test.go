package trivy

import (
	"context"
	"errors"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const goAppReport = "replicaset-test-go-app-9dc66c9c6-test-go-app"

// vr and esr name a report of the kind in the counts of reportReads.
func vr(name string) string  { return trivy.KindVulnerabilityReport + "/" + name }
func esr(name string) string { return trivy.KindExposedSecretReport + "/" + name }

// reportReads counts the report reads of the reconciler, the cache and the API reader apart, and changes what they
// return.
type reportReads struct {
	// gets counts the report GETs of the API reader by "<kind>/<name>".
	gets map[string]int
	// getNames holds the name of every report GET.
	getNames []string
	// apiLists holds the options of the report metadata lists of the API reader by list kind.
	apiLists map[string][]client.ListOptions
	// cacheLists holds the options of the report metadata lists of the cache by list kind.
	cacheLists map[string][]client.ListOptions
	// beforeGet runs before the GET of the count (1-based) of "<kind>/<name>".
	beforeGet map[string]map[int]func()
	// listed changes the item of the report name in a cache listing: the cache holds an older version.
	listed map[string]func(*metav1.PartialObjectMetadata)
	// onGet runs after every report GET with the object it filled.
	onGet func(*unstructured.Unstructured)
}

func (r *reportReads) reset() {
	r.gets, r.getNames = map[string]int{}, nil
	r.apiLists, r.cacheLists = map[string][]client.ListOptions{}, map[string][]client.ListOptions{}
}

// before runs f before the n-th GET of the report.
func (r *reportReads) before(report string, n int, f func()) {
	if r.beforeGet[report] == nil {
		r.beforeGet[report] = map[int]func(){}
	}

	r.beforeGet[report][n] = f
}

// staleRV makes the cache list the report with the resourceVersion "1", a version the cluster no longer holds.
func (r *reportReads) staleRV(name string) {
	r.listed[name] = func(m *metav1.PartialObjectMetadata) { m.ResourceVersion = "1" }
}

// countReads puts counting interceptors between the reconciler and the cluster: one for the cache, one for the API
// reader.
func (h *harness) countReads() *reportReads {
	h.t.Helper()

	reads := &reportReads{beforeGet: map[string]map[int]func(){}, listed: map[string]func(*metav1.PartialObjectMetadata){}}
	reads.reset()

	cluster, ok := h.client.(client.WithWatch)
	require.True(h.t, ok)

	h.reconciler.cache = interceptor.NewClient(cluster, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if !isReportList(list) {
				return c.List(ctx, list, opts...)
			}

			recordList(reads.cacheLists, list, opts)

			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}

			items := list.(*metav1.PartialObjectMetadataList).Items
			for i := range items {
				if edit := reads.listed[items[i].Name]; edit != nil {
					edit(&items[i])
				}
			}

			return nil
		},
	})

	h.reconciler.reader = interceptor.NewClient(cluster, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			u, isReport := obj.(*unstructured.Unstructured)
			if !isReport || u.GroupVersionKind().Group != trivy.TrivyGroup {
				return c.Get(ctx, key, obj, opts...)
			}

			id := u.GroupVersionKind().Kind + "/" + key.Name
			reads.gets[id]++
			reads.getNames = append(reads.getNames, key.Name)

			if f := reads.beforeGet[id][reads.gets[id]]; f != nil {
				f()
			}

			err := c.Get(ctx, key, obj, opts...)
			if err == nil && reads.onGet != nil {
				reads.onGet(u)
			}

			return err
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if isReportList(list) {
				recordList(reads.apiLists, list, opts)
			}

			return c.List(ctx, list, opts...)
		},
	})

	return reads
}

func recordList(lists map[string][]client.ListOptions, list client.ObjectList, opts []client.ListOption) {
	lo := client.ListOptions{}
	lo.ApplyOptions(opts)

	kind := list.(*metav1.PartialObjectMetadataList).GroupVersionKind().Kind
	lists[kind] = append(lists[kind], lo)
}

// storedReport returns the VulnerabilityReport as the cluster holds it.
func (h *harness) storedReport(name string) *unstructured.Unstructured {
	h.t.Helper()

	r := &unstructured.Unstructured{}
	r.SetGroupVersionKind(trivy.ReportGVK(trivy.KindVulnerabilityReport))
	require.NoError(h.t, h.client.Get(context.Background(), client.ObjectKey{Namespace: appNS, Name: name}, r))

	return r
}

// changeReport applies edit to the stored VulnerabilityReport: the cluster gives it a new resourceVersion.
func (h *harness) changeReport(name string, edit func(*unstructured.Unstructured)) {
	h.t.Helper()

	r := h.storedReport(name)
	edit(r)
	require.NoError(h.t, h.client.Update(context.Background(), r))
}

// markDeleted marks the stored VulnerabilityReport for deletion; a finalizer keeps it.
func (h *harness) markDeleted(name string) {
	h.t.Helper()

	h.changeReport(name, func(r *unstructured.Unstructured) { r.SetFinalizers([]string{"test/hold"}) })
	require.NoError(h.t, h.client.Delete(context.Background(), h.storedReport(name)))
}

// dropReport deletes the stored VulnerabilityReport.
func (h *harness) dropReport(name string) {
	h.t.Helper()

	require.NoError(h.t, h.client.Delete(context.Background(), h.storedReport(name)))
}

// recreateReport deletes the stored VulnerabilityReport and creates it again under the UID.
func (h *harness) recreateReport(name string, uid types.UID) {
	h.t.Helper()

	r := h.storedReport(name)
	h.dropReport(name)

	r.SetResourceVersion("")
	r.SetUID(uid)
	require.NoError(h.t, h.client.Create(context.Background(), r))
}

// setTTL0 marks the report as one Trivy Operator deletes at once.
func setTTL0(r *unstructured.Unstructured) {
	r.SetAnnotations(map[string]string{trivy.AnnotationReportTTL: "0s"})
}

// setLabel sets one label of the report; an empty value removes it.
func setLabel(key, value string) func(*unstructured.Unstructured) {
	return func(r *unstructured.Unstructured) {
		labels := r.GetLabels()
		if value == "" {
			delete(labels, key)
		} else {
			labels[key] = value
		}

		r.SetLabels(labels)
	}
}

// factVersions returns the report versions the reconciler keeps facts of for appNS, by report kind.
func (h *harness) factVersions() map[string][]reportVersion {
	h.reconciler.mu.Lock()
	defer h.reconciler.mu.Unlock()

	out := map[string][]reportVersion{}
	for v, f := range h.reconciler.facts[appNS] {
		out[f.kind] = append(out[f.kind], v)
	}

	return out
}

// uploadedReports returns the report names of the uploads into the test with the title, in order.
func (h *harness) uploadedReports(title string) []string {
	var out []string

	for _, r := range h.dd.reimports {
		if r.TestTitle == title {
			out = append(out, reportNameOf(h.t, r))
		}
	}

	return out
}

// lookAheadObjects are a Deployment web of one container app, its ReplicaSet web-rs, and the Deployments of the
// names, each with its ReplicaSet "<name>-rs".
func lookAheadObjects(names ...string) []client.Object {
	objects := append(base(), kindsOfWorkload()["Deployment"].objects("web", appContainer)...)

	for _, name := range names {
		objects = append(objects, kindsOfWorkload()["Deployment"].objects(name, appContainer)...)
	}

	return objects
}

// onReplicaSetNamed is the report of the ReplicaSet of the Deployment, of the container app, named report.
func onReplicaSetNamed(t *testing.T, deploymentName, report string) *unstructured.Unstructured {
	t.Helper()

	r := kindsOfWorkload()["Deployment"].report(t, deploymentName, appContainer)
	r.SetName(report)
	r.SetUID(types.UID("uid-" + report))

	return r
}

// onDeploymentNamed is the report on the Deployment web itself, of the container app, named report.
func onDeploymentNamed(t *testing.T, report string) *unstructured.Unstructured {
	t.Helper()

	r := kindOfWorkload{resourceKind: "Deployment", resource: ownName}.report(t, "web", appContainer)
	r.SetName(report)
	r.SetUID(types.UID("uid-" + report))

	return r
}

const webTitle = "VulnerabilityReport deployment/web/app"

func TestReconcile_FailedReportReadKeepsTheUploadErrorsOfThePass(t *testing.T) {
	h := newHarness(t, pagedObjects(t), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*unstructured.Unstructured); ok && key.Name == goAppReport {
				return errors.New("the API server is unavailable")
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})
	h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 502} }

	err := h.reconcileErr()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to import report replicaset-defectdojo-primary-55747b486-postgres",
		"the upload that failed before the read is returned")
	assert.Contains(t, err.Error(), "the API server is unavailable")
}

func TestReconcile_UnchangedPassReadsNoReportBody(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	reads := h.countReads()

	h.reconcile()
	require.Len(t, h.dd.reimports, 2)
	require.Equal(t, map[string]int{vr(goAppReport): 1, esr(goAppReport): 1}, reads.gets)

	reads.reset()
	h.reconcile()

	assert.Empty(t, reads.gets, "no report body is read")
	assert.Empty(t, reads.apiLists, "no report is listed through the API reader")
	assert.Len(t, h.dd.reimports, 2, "nothing is uploaded")
}

func TestReconcile_ChangedReportIsReadOnceAndUploadedOnce(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	reads := h.countReads()

	h.reconcile()
	h.changeReport(goAppReport, func(r *unstructured.Unstructured) { r.SetAnnotations(map[string]string{"scan": "2"}) })

	reads.reset()
	h.reconcile()

	assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets)
	assert.Equal(t, 2, h.uploadsOf(goAppTitle))
	assert.Equal(t, 1, h.uploadsOf(secretsTitle))
}

func TestReconcile_ReportReadByALookAheadIsReadAgainForItsUpload(t *testing.T) {
	h := newHarness(t, withReports(lookAheadObjects("other"),
		onReplicaSetNamed(t, "web", "a-rs"), onReplicaSetNamed(t, "other", "b-other"), onDeploymentNamed(t, "c-own")))
	reads := h.countReads()

	h.reconcile()

	assert.Equal(t, map[string]int{vr("a-rs"): 1, vr("b-other"): 1, vr("c-own"): 2}, reads.gets,
		"the look-ahead reads c-own for its facts, its upload reads it again")
	assert.Equal(t, []string{"a-rs", "c-own", "b-other", "c-own"}, reads.getNames)
	assert.Equal(t, []string{"c-own"}, h.uploadedReports(webTitle))
	assert.Equal(t, []string{"b-other"}, h.uploadedReports("VulnerabilityReport deployment/other/app"))
}

func TestReconcile_ReportThatChangedAtItsFirstReadIsDecidedOnTheReadVersion(t *testing.T) {
	sidecarTitle := "VulnerabilityReport deployment/test-go-app/sidecar"

	objects := func() []client.Object {
		objects := goAppObjects()
		objects[goAppDeployment] = deployment("test-go-app", "1", "test-go-app", sidecarContainer)

		return withReports(objects, goApp(t))
	}

	for name, tc := range map[string]struct {
		drift func(h *harness)
		check func(t *testing.T, h *harness)
	}{
		"TTL 0s appears": {
			drift: func(h *harness) { h.changeReport(goAppReport, setTTL0) },
			check: func(t *testing.T, h *harness) { assert.Empty(t, h.dd.reimports) },
		},
		"deletion timestamp appears": {
			drift: func(h *harness) { h.markDeleted(goAppReport) },
			check: func(t *testing.T, h *harness) { assert.Empty(t, h.dd.reimports) },
		},
		"container label changes": {
			drift: func(h *harness) { h.changeReport(goAppReport, setLabel(trivy.LabelContainerName, sidecarContainer)) },
			check: func(t *testing.T, h *harness) {
				assert.Zero(t, h.uploadsOf(goAppTitle), "not uploaded to the old test")
				assert.Equal(t, 1, h.uploadsOf(sidecarTitle))
			},
		},
		"same name, other UID": {
			drift: func(h *harness) { h.recreateReport(goAppReport, "uid-recreated") },
			check: func(t *testing.T, h *harness) {
				require.Equal(t, 1, h.uploadsOf(goAppTitle))

				rv := h.storedReport(goAppReport).GetResourceVersion()
				assert.True(t, strings.HasPrefix(h.markerOf(h.dd.testIDs()[0]), "uid-recreated:"+rv+":"),
					"the marker holds the read UID and resourceVersion")
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, objects())
			reads := h.countReads()
			reads.before(vr(goAppReport), 1, func() { tc.drift(h) })

			h.reconcile()

			assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets, "one GET in total")
			tc.check(t, h)
		})
	}
}

func TestReconcile_ReadVersionThatIsHeldRejectedIsNotUploaded(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.reimportErr = rejectGoApp
	reads := h.countReads()

	h.reconcile()
	require.Equal(t, 1, h.uploadsOf(goAppTitle))

	// The cache lists an earlier version; the read returns the rejected one.
	reads.staleRV(goAppReport)
	reads.reset()

	h.reconcile()

	assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets)
	assert.Equal(t, 1, h.uploadsOf(goAppTitle), "the held rejected version is not uploaded again")
}

func TestReconcile_HeldRejectedWorkloadReportIsNotRead(t *testing.T) {
	objects, own, _ := ownAndReplicaSetReports(t)

	h := newHarness(t, withReports(objects, own))
	h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 400} }
	reads := h.countReads()

	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.reconciler.facts = map[string]map[reportVersion]versionFacts{}

	reads.reset()

	h.reconcile()

	assert.Empty(t, reads.gets, "the held rejected version of a workload report takes no choice and is not read")
	assert.Len(t, h.dd.reimports, 1)
}

func TestReconcile_CandidateThatChangedAtItsLookAheadIsJudgedOnTheReadVersion(t *testing.T) {
	const otherTitle = "VulnerabilityReport deployment/other/app"

	for name, tc := range map[string]struct {
		drift func(h *harness)
		// elsewhere is true when z-report now names another live test, so it is uploaded there with a second read.
		elsewhere bool
	}{
		"TTL 0s appears":             {drift: func(h *harness) { h.changeReport("z-report", setTTL0) }},
		"deletion timestamp appears": {drift: func(h *harness) { h.markDeleted("z-report") }},
		"resource label goes missing": {drift: func(h *harness) {
			h.changeReport("z-report", setLabel(trivy.LabelResourceKind, ""))
		}},
		"container label goes missing": {drift: func(h *harness) {
			h.changeReport("z-report", setLabel(trivy.LabelContainerName, ""))
		}},
		"names another workload": {
			drift: func(h *harness) {
				h.changeReport("z-report", setLabel(trivy.LabelResourceName, "other"))
			},
			elsewhere: true,
		},
		"names another container": {drift: func(h *harness) {
			h.changeReport("z-report", setLabel(trivy.LabelContainerName, sidecarContainer))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(lookAheadObjects("other"),
				onReplicaSetNamed(t, "web", "a-report"), onDeploymentNamed(t, "z-report")))
			reads := h.countReads()
			reads.before(vr("z-report"), 1, func() { tc.drift(h) })

			h.reconcile()

			assert.Equal(t, []string{"a-report"}, h.uploadedReports(webTitle))

			if tc.elsewhere {
				assert.Equal(t, []string{"z-report"}, h.uploadedReports(otherTitle))
				assert.Equal(t, 2, reads.gets[vr("z-report")], "the look-ahead and the upload read")

				return
			}

			assert.Equal(t, 1, reads.gets[vr("z-report")], "the candidate is read once, by the look-ahead")
			assert.Len(t, h.dd.reimports, 1)
		})
	}
}

func TestReconcile_ReadVersionReplacesTheListedVersion(t *testing.T) {
	t.Run("uploaded, then unchanged", func(t *testing.T) {
		h := newHarness(t, withReports(goAppObjects(), goApp(t)))
		reads := h.countReads()
		reads.staleRV(goAppReport)

		h.reconcile()

		require.Equal(t, 1, h.uploadsOf(goAppTitle))
		rv := h.storedReport(goAppReport).GetResourceVersion()
		assert.True(t, strings.HasPrefix(h.markerOf(h.dd.testIDs()[0]), "uid-vulnerabilityreport_replicaset.json:"+rv+":"))
		assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets)

		delete(reads.listed, goAppReport)
		reads.reset()
		h.reconcile()

		assert.Empty(t, reads.gets, "the read version is the version the next pass lists")
		assert.Equal(t, 1, h.uploadsOf(goAppTitle))
	})

	t.Run("broken", func(t *testing.T) {
		h := newHarness(t, withReports(goAppObjects(), withoutField(t, goApp(t), "report", "vulnerabilities")))
		reads := h.countReads()
		reads.staleRV(goAppReport)

		h.reconcile()

		delete(reads.listed, goAppReport)
		h.reconcile()

		assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets, "read once over both passes")
		assert.Empty(t, h.dd.reimports)
	})

	t.Run("the pass fails before the reimport completes", func(t *testing.T) {
		h := newHarness(t, withReports(goAppObjects(), goApp(t)))
		h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 502} }
		reads := h.countReads()
		reads.staleRV(goAppReport)

		require.Error(t, h.reconcileErr())

		h.dd.reimportErr = nil

		delete(reads.listed, goAppReport)
		reads.reset()

		before := len(h.dd.reimports)

		h.reconcile()

		assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets, "no facts read, one read for the upload")
		assert.Equal(t, 1, len(h.dd.reimports)-before)
	})

	t.Run("the pass fails after the reimport completed", func(t *testing.T) {
		secretsFail := true

		h := newHarness(t, withReports(goAppObjects(), goApp(t)), interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if secretsFail && isReportListOf(list, trivy.KindExposedSecretReport) {
					return errors.New("down")
				}

				return c.List(ctx, list, opts...)
			},
		})
		reads := h.countReads()
		reads.staleRV(goAppReport)

		require.Error(t, h.reconcileErr())
		require.Equal(t, 1, h.uploadsOf(goAppTitle))

		secretsFail = false

		delete(reads.listed, goAppReport)
		reads.reset()

		h.reconcile()

		assert.Empty(t, reads.gets)
		assert.Equal(t, 1, h.uploadsOf(goAppTitle))
	})
}

func TestReconcile_LookAheadDriftLeavesTheWorklistIntact(t *testing.T) {
	for name, drift := range map[string]func(h *harness){
		"gone":    func(h *harness) { h.dropReport("b-report") },
		"expired": func(h *harness) { h.changeReport("b-report", setTTL0) },
		"moved":   func(h *harness) { h.changeReport("b-report", setLabel(trivy.LabelContainerName, "elsewhere")) },
		"broken": func(h *harness) {
			h.changeReport("b-report", func(r *unstructured.Unstructured) {
				unstructured.RemoveNestedField(r.Object, "report", "vulnerabilities")
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(lookAheadObjects(),
				onReplicaSetNamed(t, "web", "a-report"), onDeploymentNamed(t, "b-report"), onDeploymentNamed(t, "c-report")))
			reads := h.countReads()
			reads.before(vr("b-report"), 1, func() { drift(h) })

			h.reconcile()

			assert.Equal(t, []string{"c-report"}, h.uploadedReports(webTitle), "c-report is selected and uploaded")
			assert.Len(t, h.dd.reimports, 1, "only the chosen report is reimported")
			assert.Equal(t, 1, reads.gets[vr("b-report")], "b-report is not read again at its own turn")
			assert.NotContains(t, reads.getNames, "", "no GET without a name")
		})
	}

	t.Run("the upload read returns a later version than the look-ahead", func(t *testing.T) {
		h := newHarness(t, withReports(lookAheadObjects(), onReplicaSetNamed(t, "web", "a-report"), onDeploymentNamed(t, "c-report")))
		reads := h.countReads()
		reads.staleRV("c-report")
		reads.before(vr("c-report"), 2, func() {
			h.changeReport("c-report", func(r *unstructured.Unstructured) { r.SetAnnotations(map[string]string{"scan": "3"}) })
		})

		require.NoError(t, h.reconcileErr())

		assert.Equal(t, 2, reads.gets[vr("c-report")], "the look-ahead and the upload read; no read of the listed version")
		assert.Empty(t, h.uploadedReports(webTitle), "the upload is deferred and the report on the ReplicaSet loses")
	})
}

func TestReconcile_ReportGoneAtItsFirstReadTakesNoChoice(t *testing.T) {
	h := newHarness(t, withReports(lookAheadObjects(), onReplicaSetNamed(t, "web", "a-report"), onReplicaSetNamed(t, "web", "b-report")))
	reads := h.countReads()
	reads.before(vr("a-report"), 1, func() { h.dropReport("a-report") })

	h.reconcile()

	assert.Equal(t, []string{"b-report"}, h.uploadedReports(webTitle))
}

func TestReconcile_ReportThatChangedAtItsUploadReadIsNotUploaded(t *testing.T) {
	for name, tc := range map[string]struct {
		drift func(h *harness)
		after func(h *harness)
	}{
		"changed": {drift: func(h *harness) {
			h.changeReport(goAppReport, func(r *unstructured.Unstructured) { r.SetAnnotations(map[string]string{"scan": "2"}) })
		}},
		"gone": {
			drift: func(h *harness) { h.dropReport(goAppReport) },
			after: func(h *harness) { h.setReport(goApp(h.t)) },
		},
		"created again": {drift: func(h *harness) { h.recreateReport(goAppReport, "uid-recreated") }},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), goApp(t)))
			reads := h.countReads()
			testID := h.onlyTest()
			marker := h.markerOf(testID)

			// Another app tag changes the request: the known version needs an upload read.
			dep := &appsv1.Deployment{}
			require.NoError(t, h.client.Get(context.Background(), client.ObjectKey{Namespace: appNS, Name: "test-go-app"}, dep))
			dep.Labels = map[string]string{"app.kubernetes.io/instance": "web"}
			h.update(dep)

			reads.reset()
			reads.before(vr(goAppReport), 1, func() { tc.drift(h) })

			require.NoError(t, h.reconcileErr())

			assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets)
			assert.Len(t, h.dd.reimports, 1, "nothing is uploaded")
			assert.Equal(t, marker, h.markerOf(testID), "the test keeps its earlier marker")
			assert.Empty(t, h.dd.closed)

			if tc.after != nil {
				tc.after(h)
			}

			h.reconcile()

			require.Len(t, h.dd.reimports, 2, "the next pass uploads the report")
			assert.Equal(t, "web", appTagOf(h.dd.reimports[1].Tags))
		})
	}
}

func TestReconcile_BrokenReportIsReadOnceOverTwoPasses(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), withoutField(t, goApp(t), "report", "vulnerabilities")))
	reads := h.countReads()

	for range 2 {
		assert.Contains(t, h.reconcileLogged(), "Skipped a broken report")
	}

	assert.Equal(t, map[string]int{vr(goAppReport): 1}, reads.gets)
	assert.Empty(t, h.dd.reimports)
}

func TestReconcile_AfterARestartEachEligibleReportVersionIsReadOnce(t *testing.T) {
	historical := goApp(t)
	historical.SetName("replicaset-test-go-app-5f4d8c7b9-test-go-app")
	historical.SetUID("uid-historical")
	historical.SetLabels(map[string]string{
		trivy.LabelResourceKind:      "ReplicaSet",
		trivy.LabelResourceName:      "test-go-app-5f4d8c7b9",
		trivy.LabelResourceNamespace: appNS,
		trivy.LabelContainerName:     "test-go-app",
	})

	objects := append(goAppObjects(), replicaSet("test-go-app-5f4d8c7b9", "test-go-app", "0"))

	h := newHarness(t, withReports(objects, goApp(t), goAppSecrets(t), historical))
	reads := h.countReads()

	h.reconcile()
	require.Len(t, h.dd.reimports, 2)

	h.restart()
	reads.reset()

	h.reconcile()

	assert.Equal(t, map[string]int{vr(goAppReport): 1, esr(goAppReport): 1}, reads.gets,
		"the historical report is not read")
	assert.Len(t, h.dd.reimports, 2, "the tests hold the markers")
}

func TestReconcile_KindNotServedAtStartIsListedThroughTheAPIReader(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	h.reconciler.watched = []string{trivy.KindExposedSecretReport}
	reads := h.countReads()

	h.reconcile()

	assert.Equal(t, []string{"ExposedSecretReportList"}, slices.Collect(maps.Keys(reads.cacheLists)),
		"no cache list runs for the kind that is not watched")
	require.Len(t, reads.apiLists["VulnerabilityReportList"], 1)
	assert.Equal(t, int64(500), reads.apiLists["VulnerabilityReportList"][0].Limit)
	assert.Equal(t, 1, h.uploadsOf(goAppTitle))
}

func TestReconcile_WatchedKindIsListedOnceFromTheCache(t *testing.T) {
	objects, own, onReplicaSet := ownAndReplicaSetReports(t)
	// The report of the ReplicaSet comes first, so the pass looks for the report on the Deployment.
	onReplicaSet.SetName("a-" + onReplicaSet.GetName())

	h := newHarness(t, withReports(objects, own, onReplicaSet))
	reads := h.countReads()

	h.reconcile()

	one := []client.ListOptions{{Namespace: appNS}}
	assert.Equal(t, map[string][]client.ListOptions{"VulnerabilityReportList": one, "ExposedSecretReportList": one},
		reads.cacheLists, "one list per kind, of the namespace, without Limit or Continue")
	assert.Empty(t, reads.apiLists)
	assert.Equal(t, []string{own.GetName()}, h.uploadedReports(webTitle))
}

func TestReconcile_EqualReportsListedInReverseGiveOneUpload(t *testing.T) {
	h := newHarness(t, withReports(lookAheadObjects(), onReplicaSetNamed(t, "web", "z-report"), onReplicaSetNamed(t, "web", "a-report")),
		descendingReports())

	h.reconcile()
	h.reconcile()

	assert.Equal(t, []string{"a-report"}, h.uploadedReports(webTitle))
}

func TestReconcile_FactsOfAChangingReportStayBoundedUnderFailure(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.dd.reimportErr = func(defectdojo.ReimportRequest) error { return &defectdojo.APIError{StatusCode: 502} }

	for i := range 3 {
		h.changeReport(goAppReport, func(r *unstructured.Unstructured) {
			r.SetAnnotations(map[string]string{"scan": string(rune('a' + i))})
		})
		require.Error(t, h.reconcileErr())
	}

	latest := versionOf(h.storedReport(goAppReport))
	assert.Equal(t, map[string][]reportVersion{trivy.KindVulnerabilityReport: {latest}}, h.factVersions())

	h.dd.reimportErr = nil
	before := len(h.dd.reimports)

	h.reconcile()

	assert.Equal(t, 1, len(h.dd.reimports)-before, "the recovery uploads the report once")
}

func TestReconcile_FactsOfAKindWhoseListingDidNotCompleteAreKept(t *testing.T) {
	failVulnerabilities := false

	for name, tc := range map[string]struct {
		unwatch bool
		funcs   interceptor.Funcs
		pass    func(h *harness, fail *bool)
	}{
		"never attempted: cancelled before the first listing": {
			pass: func(h *harness, _ *bool) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := h.reconciler.Reconcile(ctx, namespaceRequest(appNS))
				require.ErrorIs(h.t, err, context.Canceled)
			},
		},
		"never reached: the first kind fails": {
			funcs: failingList(trivy.KindVulnerabilityReport, &failVulnerabilities, errors.New("down")),
			pass:  failingPass,
		},
		"interrupted on a later page": {
			unwatch: true,
			funcs:   failingLaterPage(&failVulnerabilities),
			pass:    failingPass,
		},
		"not served": {
			funcs: failingList(trivy.KindVulnerabilityReport, &failVulnerabilities, noKindMatch()),
			pass: func(h *harness, fail *bool) {
				*fail = true

				h.reconcile()
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			failVulnerabilities = false

			h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)), tc.funcs)
			if tc.unwatch {
				h.unwatch()
			}

			h.reconcile()

			kept := h.factVersions()
			require.Len(t, kept[trivy.KindVulnerabilityReport], 1)
			require.Len(t, kept[trivy.KindExposedSecretReport], 1)

			h.dropReport(goAppReport)
			tc.pass(h, &failVulnerabilities)

			assert.Equal(t, kept[trivy.KindVulnerabilityReport], h.factVersions()[trivy.KindVulnerabilityReport],
				"the facts of the kind are kept")
		})
	}
}

// failingPass fails the listing of the VulnerabilityReports and runs a pass that fails.
func failingPass(h *harness, fail *bool) {
	*fail = true

	require.Error(h.t, h.reconcileErr())
}

// failingList fails the metadata lists of the kind with err while *fail is true.
func failingList(kind string, fail *bool, err error) interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if *fail && isReportListOf(list, kind) {
				return err
			}

			return c.List(ctx, list, opts...)
		},
	}
}

// failingLaterPage lists the VulnerabilityReports in two pages and fails the second while *fail is true.
func failingLaterPage(fail *bool) interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if !isReportListOf(list, trivy.KindVulnerabilityReport) {
				return c.List(ctx, list, opts...)
			}

			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)

			if !*fail {
				return c.List(ctx, list, opts...)
			}

			if lo.Continue != "" {
				return errors.New("down")
			}

			meta := list.(*metav1.PartialObjectMetadataList)
			meta.SetContinue("page-2")

			return nil
		},
	}
}

func TestReconcile_FactsOfACompletedEmptyListingAndOfAReleasedNamespaceAreDropped(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))

	h.reconcile()
	require.Len(t, h.factVersions(), 2)

	h.dropReport(goAppReport)
	h.reconcile()

	assert.NotContains(t, h.factVersions(), trivy.KindVulnerabilityReport, "a completed empty listing drops the facts")
	assert.Contains(t, h.factVersions(), trivy.KindExposedSecretReport)

	h.reconciler.config.ExcludeNamespaces = []string{appNS}
	h.reconcile()

	assert.Empty(t, h.factVersions(), "a released namespace drops every fact")
}

func TestReconcile_PanicAfterTheListingKeepsTheFactsOfTheEffectiveVersions(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	reads := h.countReads()

	h.reconcile()

	earlier := versionOf(h.storedReport(goAppReport))
	require.Equal(t, map[string][]reportVersion{trivy.KindVulnerabilityReport: {earlier}}, h.factVersions())

	h.changeReport(goAppReport, func(r *unstructured.Unstructured) { r.SetAnnotations(map[string]string{"scan": "2"}) })
	reads.staleRV(goAppReport)

	h.dd.reimportErr = func(defectdojo.ReimportRequest) error { panic("worker killed") }

	assert.Panics(t, func() { _ = h.reconcileErr() })

	read := versionOf(h.storedReport(goAppReport))
	assert.Equal(t, map[string][]reportVersion{trivy.KindVulnerabilityReport: {read}}, h.factVersions(),
		"the facts hold the read version only: the listed and the earlier version are dropped")
}

func TestReconcile_DuplicateReportKindIsListedOnce(t *testing.T) {
	env := requiredEnv()
	env[EnvReportKinds] = "VulnerabilityReport,VulnerabilityReport"

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)

	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconciler.config.ReportKinds = cfg.ReportKinds
	reads := h.countReads()

	h.reconcile()

	assert.Equal(t, map[string][]client.ListOptions{"VulnerabilityReportList": {{Namespace: appNS}}}, reads.cacheLists)
	assert.Equal(t, 1, h.uploadsOf(goAppTitle))
}

// liveBodies counts the report bodies the reader handed out and the garbage collector has not freed.
type liveBodies struct {
	handed, freed atomic.Int64
	max           int64
}

// settle runs the finalizers of the objects that are unreachable now. The finalizers queued by one collection all
// run before those of the next one.
func settle() {
	for range 2 {
		done := make(chan struct{})
		sentinel(done)
		runtime.GC()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

// sentinel allocates an object that becomes unreachable at once and closes done when it is finalized. It is larger
// than the tiny allocator's blocks, whose objects may never be finalized.
func sentinel(done chan struct{}) {
	s := &struct {
		next *int
		pad  [64]byte
	}{}

	runtime.SetFinalizer(s, func(*struct {
		next *int
		pad  [64]byte
	}) {
		close(done)
	})
}

func TestReconcile_PassHoldsAtMostTwoReportBodies(t *testing.T) {
	h := newHarness(t, withReports(lookAheadObjects("d1", "d2", "d3"),
		onReplicaSetNamed(t, "d1", "a1"), onReplicaSetNamed(t, "d2", "a2"), onReplicaSetNamed(t, "d3", "a3"),
		onReplicaSetNamed(t, "web", "b-rs"), onDeploymentNamed(t, "c-own")))
	reads := h.countReads()

	var live liveBodies

	for _, name := range []string{"a1", "a2", "a3", "b-rs", "c-own"} {
		for n := 1; n <= 2; n++ {
			reads.before(vr(name), n, func() {
				// A finalizer can lag a collection on a loaded machine: settle again before counting a third body.
				now := int64(0)

				for range 3 {
					settle()

					if now = live.handed.Load() - live.freed.Load() + 1; now <= 2 {
						break
					}
				}

				live.max = max(live.max, now)
			})
		}
	}

	reads.onGet = func(body *unstructured.Unstructured) {
		live.handed.Add(1)
		runtime.SetFinalizer(body, func(*unstructured.Unstructured) { live.freed.Add(1) })
	}

	h.reconcile()

	require.Equal(t, 2, reads.gets[vr("c-own")], "the pass holds the body of b-rs while it reads c-own ahead")
	assert.Equal(t, int64(2), live.max, "a deciding body and one look-ahead body at most")
}
