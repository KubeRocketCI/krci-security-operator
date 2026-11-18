package trivy

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// reconcileLogged reconciles the namespace appNS and returns what the pass logged.
func (h *harness) reconcileLogged() string {
	h.t.Helper()

	var lines []string

	log := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 0})

	_, err := h.reconciler.Reconcile(ctrl.LoggerInto(context.Background(), log), namespaceRequest(appNS))
	require.NoError(h.t, err)

	return strings.Join(lines, "\n")
}

// findingStatuses counts the findings of the only test by status.
func (h *harness) findingStatuses() map[string]int {
	h.t.Helper()

	ids := h.dd.testIDs()
	require.Len(h.t, ids, 1)

	out := map[string]int{}
	for _, f := range h.dd.findingsIn(ids[0]) {
		out[f.status()]++
	}

	return out
}

func withoutField(t *testing.T, report *unstructured.Unstructured, fields ...string) *unstructured.Unstructured {
	t.Helper()

	unstructured.RemoveNestedField(report.Object, fields...)

	return report
}

func withReportBlock(t *testing.T, report *unstructured.Unstructured, block map[string]any) *unstructured.Unstructured {
	t.Helper()

	require.NoError(t, unstructured.SetNestedMap(report.Object, block, "report"))

	return report
}

func withLabels(t *testing.T, report *unstructured.Unstructured, labels map[string]string) *unstructured.Unstructured {
	t.Helper()

	require.NoError(t, unstructured.SetNestedStringMap(report.Object, labels, "metadata", "labels"))

	return report
}

func withoutLabel(report *unstructured.Unstructured, key string) *unstructured.Unstructured {
	labels := report.GetLabels()
	delete(labels, key)
	report.SetLabels(labels)

	return report
}

// brokenReportCase is a report that is never uploaded, as the update of the report that was imported before.
type brokenReportCase struct {
	original func(*testing.T) *unstructured.Unstructured
	broken   func(*testing.T, *unstructured.Unstructured) *unstructured.Unstructured
}

// brokenReportCases are keyed by their description.
func brokenReportCases() map[string]brokenReportCase {
	vulnerability := func(broken func(*testing.T, *unstructured.Unstructured) *unstructured.Unstructured) brokenReportCase {
		return brokenReportCase{original: goApp, broken: broken}
	}
	exposedSecret := func(broken func(*testing.T, *unstructured.Unstructured) *unstructured.Unstructured) brokenReportCase {
		return brokenReportCase{original: goAppSecrets, broken: broken}
	}

	withoutLabels := func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withoutField(t, r, "metadata", "labels")
	}
	withEmptyLabels := func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withLabels(t, r, map[string]string{})
	}
	withOtherLabelsOnly := func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withLabels(t, r, map[string]string{"resource-spec-hash": "6b7dd78d66", trivy.LabelContainerName: "test-go-app"})
	}
	withoutResourceKind := func(_ *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withoutLabel(r, trivy.LabelResourceKind)
	}
	withoutResourceName := func(_ *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withoutLabel(r, trivy.LabelResourceName)
	}
	withoutContainerName := func(_ *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withoutLabel(r, trivy.LabelContainerName)
	}
	withoutReportBlock := func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withoutField(t, r, "report")
	}
	withEmptyReportBlock := func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
		return withReportBlock(t, r, map[string]any{})
	}
	withoutList := func(field string) func(*testing.T, *unstructured.Unstructured) *unstructured.Unstructured {
		return func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
			return withoutField(t, r, "report", field)
		}
	}
	withNullList := func(field string) func(*testing.T, *unstructured.Unstructured) *unstructured.Unstructured {
		return func(t *testing.T, r *unstructured.Unstructured) *unstructured.Unstructured {
			report := withoutField(t, r, "report", field)
			require.NoError(t, unstructured.SetNestedField(report.Object, nil, "report", field))

			return report
		}
	}

	return map[string]brokenReportCase{
		"vulnerability report without labels":              vulnerability(withoutLabels),
		"vulnerability report with empty labels":           vulnerability(withEmptyLabels),
		"vulnerability report with other labels only":      vulnerability(withOtherLabelsOnly),
		"vulnerability report without the resource kind":   vulnerability(withoutResourceKind),
		"vulnerability report without the resource name":   vulnerability(withoutResourceName),
		"vulnerability report without the container name":  vulnerability(withoutContainerName),
		"vulnerability report without the report block":    vulnerability(withoutReportBlock),
		"vulnerability report with an empty report block":  vulnerability(withEmptyReportBlock),
		"vulnerability report without its vulnerabilities": vulnerability(withoutList("vulnerabilities")),
		"vulnerability report with null vulnerabilities":   vulnerability(withNullList("vulnerabilities")),
		"exposed secret report without labels":             exposedSecret(withoutLabels),
		"exposed secret report with other labels only":     exposedSecret(withOtherLabelsOnly),
		"exposed secret report without the resource kind":  exposedSecret(withoutResourceKind),
		"exposed secret report without the resource name":  exposedSecret(withoutResourceName),
		"exposed secret report without the container name": exposedSecret(withoutContainerName),
		"exposed secret report without the report block":   exposedSecret(withoutReportBlock),
		"exposed secret report with an empty report block": exposedSecret(withEmptyReportBlock),
		"exposed secret report without its secrets":        exposedSecret(withoutList("secrets")),
		"exposed secret report with null secrets":          exposedSecret(withNullList("secrets")),
	}
}

func TestReconcile_BrokenReportKeepsTheFindingsOfItsTest(t *testing.T) {
	for name, tc := range brokenReportCases() {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), tc.original(t)))
			h.reconcile()

			before := h.findingStatuses()
			require.NotEmpty(t, before)
			require.Zero(t, before[statusClosed])

			h.setReport(tc.broken(t, tc.original(t)))

			logged := h.reconcileLogged()

			assert.Len(t, h.dd.reimports, 1, "the broken report is not uploaded")
			assert.Empty(t, h.dd.closed, "the test of the broken report stays open")
			assert.Equal(t, before, h.findingStatuses())
			assert.Contains(t, logged, "Skipped a broken report")
		})
	}
}

func TestReconcile_BrokenReportIsSkippedAgainOnTheNextPass(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconcile()

	before := h.findingStatuses()

	h.setReport(withoutField(t, goApp(t), "report", "vulnerabilities"))

	h.reconcile()
	h.reconcile()

	assert.Len(t, h.dd.reimports, 1)
	assert.Empty(t, h.dd.closed)
	assert.Equal(t, before, h.findingStatuses())
}

func TestReconcile_ReportThatIsWholeAgainIsUploaded(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goApp(t)))
	h.reconcile()

	h.setReport(withoutField(t, goApp(t), "report", "vulnerabilities"))
	h.reconcile()
	require.Len(t, h.dd.reimports, 1)

	h.setReport(goApp(t))
	h.reconcile()

	assert.Len(t, h.dd.reimports, 2)
	assert.Equal(t, map[string]int{statusActive: 2}, h.findingStatuses())
}

func TestReconcile_EmptyReportClosesTheFindingsOfItsTest(t *testing.T) {
	tests := map[string]struct {
		original func(*testing.T) *unstructured.Unstructured
		field    string
	}{
		"vulnerability report":  {original: goApp, field: "vulnerabilities"},
		"exposed secret report": {original: goAppSecrets, field: "secrets"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(goAppObjects(), tc.original(t)))
			h.reconcile()

			before := h.findingStatuses()
			require.NotZero(t, before[statusActive])

			empty := tc.original(t)
			require.NoError(t, unstructured.SetNestedSlice(empty.Object, []any{}, "report", tc.field))
			h.setReport(empty)

			h.reconcile()

			assert.Len(t, h.dd.reimports, 2, "an empty report is uploaded")

			assert.Equal(t, map[string]int{statusClosed: before[statusActive]}, h.findingStatuses())
		})
	}
}

func TestReconcile_BrokenReportOfAWorkloadThatIsGoneDoesNotKeepItsTestOpen(t *testing.T) {
	objects := goAppObjects()
	h := newHarness(t, withReports(objects, goApp(t)))
	h.reconcile()

	h.setReport(withoutField(t, goApp(t), "report", "vulnerabilities"))
	h.remove(objects[goAppDeployment])
	h.remove(objects[goAppDeployment+1])

	h.reconcile()

	assert.Equal(t, 1, len(h.dd.closed), "the namespace rules still close the test of a workload that is gone")
	assert.Zero(t, h.findingStatuses()[statusActive])
}

// activeFindingsOf counts the active findings of the test with the title.
func (h *harness) activeFindingsOf(title string) int {
	h.t.Helper()

	for _, id := range h.dd.testIDs() {
		if h.dd.test(id).title != title {
			continue
		}

		active := 0

		for _, f := range h.dd.findingsIn(id) {
			if f.status() == statusActive {
				active++
			}
		}

		return active
	}

	h.t.Fatalf("no test titled %q", title)

	return 0
}

func TestReconcile_ReportWithoutLabelsHoldsNoTestAndClosesNone(t *testing.T) {
	for name, unlabelled := range map[string]func(*testing.T) *unstructured.Unstructured{
		"vulnerability report":  goApp,
		"exposed secret report": goAppSecrets,
	} {
		t.Run(name, func(t *testing.T) {
			objects := goAppObjects()
			h := newHarness(t, withReports(objects, goApp(t), goAppSecrets(t)))
			h.reconcile()

			require.NotZero(t, h.activeFindingsOf(goAppTitle))
			require.NotZero(t, h.activeFindingsOf(secretsTitle))

			h.setReport(withoutField(t, unlabelled(t), "metadata", "labels"))
			h.reconcile()

			assert.NotZero(t, h.activeFindingsOf(goAppTitle), "the workload is running")
			assert.NotZero(t, h.activeFindingsOf(secretsTitle), "the workload is running")

			h.remove(objects[goAppDeployment])
			h.remove(objects[goAppDeployment+1])

			h.reconcile()

			assert.Zero(t, h.activeFindingsOf(goAppTitle), "the workload is gone")
			assert.Zero(t, h.activeFindingsOf(secretsTitle), "the workload is gone")
		})
	}
}

func TestReconcile_WorkloadNameInTheAnnotationIsResolved(t *testing.T) {
	report := goApp(t)
	name := report.GetLabels()[trivy.LabelResourceName]

	report.SetLabels(withoutLabel(report, trivy.LabelResourceName).GetLabels())
	report.SetAnnotations(map[string]string{trivy.LabelResourceName: name})

	h := newHarness(t, withReports(goAppObjects(), report))
	h.reconcile()

	require.Len(t, h.dd.reimports, 1, "a report with the name in the annotation is not broken")
	assert.Equal(t, goAppTitle, h.dd.reimports[0].TestTitle)

	statuses := h.dd.statuses(h.dd.testIDs()[0], goAppService)
	assert.NotEmpty(t, statuses, "the parser reads the name the operator writes to the labels")
}
