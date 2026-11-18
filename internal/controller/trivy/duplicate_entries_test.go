package trivy

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// goAppWithRepeat is the go app report with its first entry repeated at the end: three entries, two distinct.
func goAppWithRepeat(t *testing.T) *unstructured.Unstructured {
	t.Helper()

	report := goApp(t)

	vulns, _, err := unstructured.NestedSlice(report.Object, "report", "vulnerabilities")
	require.NoError(t, err)
	require.Len(t, vulns, 2)

	require.NoError(t, unstructured.SetNestedSlice(report.Object, append(vulns, vulns[0]), "report", "vulnerabilities"))

	return report
}

func TestReconcile_RepeatedReportEntryIsOneFindingAndStaysOpenOnEveryReimport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goAppWithRepeat(t)))
	testID := h.onlyTest()

	assert.Equal(t, map[string]string{cveKept: statusActive, cveFixed: statusActive}, h.dd.statuses(testID, goAppService))
	assert.Len(t, h.dd.findingsIn(testID), 2, "one finding per distinct entry")

	before := h.dd.findingsIn(testID)

	for pass := 2; pass <= 3; pass++ {
		h.setReport(goAppWithRepeat(t))
		h.reconcile()

		require.Len(t, h.dd.reimports, pass, "the changed report is uploaded again")
		assert.Equal(t, before, h.dd.findingsIn(testID), "pass %d: no finding is closed or added", pass)
	}
}

// goAppSecretsWithRepeat is the go app secret report with its entry repeated and a second distinct entry:
// three entries, two distinct.
func goAppSecretsWithRepeat(t *testing.T) *unstructured.Unstructured {
	t.Helper()

	report := goAppSecrets(t)

	secrets, _, err := unstructured.NestedSlice(report.Object, "report", "secrets")
	require.NoError(t, err)
	require.Len(t, secrets, 1)

	entry, ok := secrets[0].(map[string]any)
	require.True(t, ok)

	other := maps.Clone(entry)
	other["ruleID"] = "aws-secret-access-key"
	other["title"] = "AWS Secret Access Key"

	require.NoError(t, unstructured.SetNestedSlice(report.Object, []any{entry, entry, other}, "report", "secrets"))

	return report
}

func TestReconcile_RepeatedSecretEntryIsOneFindingAndStaysOpenOnEveryReimport(t *testing.T) {
	h := newHarness(t, withReports(goAppObjects(), goAppSecretsWithRepeat(t)))
	testID := h.onlyTest()

	statuses := map[string]string{
		"Secret detected in app/.env - AWS Access Key ID":     statusActive,
		"Secret detected in app/.env - AWS Secret Access Key": statusActive,
	}

	assert.Equal(t, statuses, h.dd.statuses(testID, goAppService))
	assert.Len(t, h.dd.findingsIn(testID), 2, "one finding per distinct entry")

	before := h.dd.findingsIn(testID)

	for pass := 2; pass <= 3; pass++ {
		h.setReport(goAppSecretsWithRepeat(t))
		h.reconcile()

		require.Len(t, h.dd.reimports, pass, "the changed report is uploaded again")
		assert.Equal(t, before, h.dd.findingsIn(testID), "pass %d: no finding is closed or added", pass)
	}
}

// hashesOf returns the hash codes the fake computes for the findings of the report.
func hashesOf(t *testing.T, report map[string]any) []string {
	t.Helper()

	raw, err := json.Marshal(report)
	require.NoError(t, err)

	parsed, err := parseTrivyOperatorReport(raw)
	require.NoError(t, err)

	out := make([]string, 0, len(parsed))
	for _, p := range parsed {
		out = append(out, p.hash())
	}

	return out
}

// assertOneEntryPerHash checks that Payload keeps one entry per hash code of the report as DefectDojo parses it:
// the hash codes of the payload are pairwise distinct and are the set of the hash codes before.
func assertOneEntryPerHash(t *testing.T, report *unstructured.Unstructured, workload trivy.Workload) {
	t.Helper()

	payload := trivy.Payload(report, workload)

	// The report with the labels of the payload, so that both parse to the same service and description.
	uncollapsed := report.DeepCopy()
	uncollapsed.Object["metadata"] = payload["metadata"]

	before := hashesOf(t, uncollapsed.Object)
	after := hashesOf(t, payload)

	distinct := slices.Compact(slices.Sorted(slices.Values(before)))

	require.Greater(t, len(before), len(distinct), "the report holds repeated entries")
	assert.Len(t, after, len(distinct), "one entry per hash code")
	assert.Equal(t, distinct, slices.Sorted(slices.Values(after)), "the same hash codes, each once")
}

func TestPayload_KeepsOneEntryPerDefectDojoHashCode(t *testing.T) {
	t.Run("vulnerability report of the testbed", func(t *testing.T) {
		report := fixture(t, "vulnerabilityreport_argocd_server_repeats.json")

		assertOneEntryPerHash(t, report, trivy.Workload{Kind: "deployment", Name: "argocd-server"})
	})

	t.Run("entries that differ in an absent field, null, None or case", func(t *testing.T) {
		report := goApp(t)

		vulns, _, err := unstructured.NestedSlice(report.Object, "report", "vulnerabilities")
		require.NoError(t, err)

		base, ok := vulns[0].(map[string]any)
		require.True(t, ok)

		absent := maps.Clone(base)
		delete(absent, "fixedVersion")
		delete(absent, "title")

		null := maps.Clone(base)
		null["fixedVersion"] = nil
		null["title"] = nil

		none := maps.Clone(base)
		none["fixedVersion"] = "None"
		none["title"] = "None"

		upper := maps.Clone(base)
		upper["vulnerabilityID"] = strings.ToUpper(base["vulnerabilityID"].(string)) //nolint:forcetypeassert
		upper["resource"] = strings.ToUpper(base["resource"].(string))               //nolint:forcetypeassert
		upper["title"] = "STRASSE"

		other := maps.Clone(base)
		other["title"] = "Straße"

		require.NoError(t, unstructured.SetNestedSlice(report.Object,
			[]any{base, absent, null, none, upper, other}, "report", "vulnerabilities"))

		assertOneEntryPerHash(t, report, trivy.Workload{Kind: "deployment", Name: "test-go-app"})
	})

	t.Run("exposed secret report", func(t *testing.T) {
		report := goAppSecrets(t)

		secrets, _, err := unstructured.NestedSlice(report.Object, "report", "secrets")
		require.NoError(t, err)
		require.Len(t, secrets, 1)

		entry, ok := secrets[0].(map[string]any)
		require.True(t, ok)

		moved := maps.Clone(entry)
		moved["target"] = "app/other.env"

		rematched := maps.Clone(entry)
		rematched["match"] = "AWS_ACCESS_KEY_ID=other"

		require.NoError(t, unstructured.SetNestedSlice(report.Object,
			[]any{entry, moved, rematched, entry}, "report", "secrets"))

		assertOneEntryPerHash(t, report, trivy.Workload{Kind: "deployment", Name: "test-go-app"})
	})
}
