package trivy

import (
	"maps"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var appWorkload = Workload{"deployment", "test-go-app"}

func vulnEntry() map[string]any {
	return map[string]any{
		"vulnerabilityID":  "CVE-2026-0001",
		"resource":         "libssl",
		"installedVersion": "3.0.0",
		"fixedVersion":     "3.0.1",
		"severity":         "HIGH",
		"title":            "libssl: overflow",
		"score":            7.5,
		"target":           "",
		"links":            []any{},
	}
}

func secretEntry() map[string]any {
	return map[string]any{
		"ruleID":   "aws-access-key-id",
		"category": "AWS",
		"match":    "AWS_ACCESS_KEY_ID=****",
		"severity": "CRITICAL",
		"target":   "app/.env",
		"title":    "AWS Access Key ID",
	}
}

// reportOf returns a report of the kind from the go app fixture with the entries as its result list.
func reportOf(t *testing.T, kind string, entries ...any) *unstructured.Unstructured {
	t.Helper()

	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	report.SetKind(kind)

	if entries == nil {
		entries = []any{}
	}

	require.NoError(t, unstructured.SetNestedSlice(report.Object, entries, "report", resultFields[kind]))

	return report
}

func entriesOf(t *testing.T, payload map[string]any, kind string) []any {
	t.Helper()

	block, ok := payload["report"].(map[string]any)
	require.True(t, ok)

	entries, ok := block[resultFields[kind]].([]any)
	require.True(t, ok)

	return entries
}

// with returns a copy of the entry with the field set; a nil value removes the field.
func with(entry map[string]any, field string, value any) map[string]any {
	out := maps.Clone(entry)

	if value == nil {
		delete(out, field)
	} else {
		out[field] = value
	}

	return out
}

func TestPayload_RepeatedEntryIsSentOnceAtTheFirstPosition(t *testing.T) {
	first := vulnEntry()
	other := with(vulnEntry(), "vulnerabilityID", "CVE-2026-0002")
	repeat := with(vulnEntry(), "score", 5.9)

	report := reportOf(t, KindVulnerabilityReport, first, other, repeat, vulnEntry())

	got := entriesOf(t, Payload(report, appWorkload), KindVulnerabilityReport)

	assert.Equal(t, []any{first, other}, got, "the first entry is kept, in report order")
}

func TestPayload_EntriesThatDifferInAKeyFieldAreKept(t *testing.T) {
	for kind, fields := range map[string]map[string]any{
		KindVulnerabilityReport: {
			"vulnerabilityID": "CVE-2026-0002", "resource": "libcrypto", "installedVersion": "3.0.1",
			"severity": "LOW", "title": "other title", "fixedVersion": "3.0.2",
		},
		KindExposedSecretReport: {
			"target": "app/other", "title": "other title", "category": "GCP", "match": "other",
			"severity": "HIGH", "ruleID": "other-rule",
		},
	} {
		base := vulnEntry()
		if kind == KindExposedSecretReport {
			base = secretEntry()
		}

		for field, value := range fields {
			t.Run(kind+"/"+field, func(t *testing.T) {
				report := reportOf(t, kind, base, with(base, field, value))

				assert.Len(t, entriesOf(t, Payload(report, appWorkload), kind), 2)
			})
		}
	}
}

func TestPayload_AbsentFieldDiffersFromEmptyField(t *testing.T) {
	report := reportOf(t, KindVulnerabilityReport,
		with(vulnEntry(), "fixedVersion", ""), with(vulnEntry(), "fixedVersion", nil))

	assert.Len(t, entriesOf(t, Payload(report, appWorkload), KindVulnerabilityReport), 2)
}

func TestPayload_EntriesThatDifferOnlyOutsideTheKeyAreCollapsed(t *testing.T) {
	variant := vulnEntry()
	variant["score"] = 5.9
	variant["target"] = "usr/bin/app"
	variant["packagePath"] = "usr/bin/app"
	variant["links"] = []any{"https://example.com"}
	variant["primaryLink"] = "https://example.com"

	report := reportOf(t, KindVulnerabilityReport, vulnEntry(), variant)

	assert.Equal(t, []any{vulnEntry()}, entriesOf(t, Payload(report, appWorkload), KindVulnerabilityReport))

	secret := secretEntry()
	secret["extra"] = "x"

	report = reportOf(t, KindExposedSecretReport, secretEntry(), secret)

	assert.Equal(t, []any{secretEntry()}, entriesOf(t, Payload(report, appWorkload), KindExposedSecretReport))
}

func TestPayload_NoRepeatedEntryChangesNothing(t *testing.T) {
	report := reportOf(t, KindVulnerabilityReport, vulnEntry(), with(vulnEntry(), "vulnerabilityID", "CVE-2026-0002"))

	payload := Payload(report, appWorkload)

	assert.Equal(t, report.Object["report"], payload["report"])

	original, ok := report.Object["report"].(map[string]any)
	require.True(t, ok)

	sent, ok := payload["report"].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, reflect.ValueOf(original).Pointer(), reflect.ValueOf(sent).Pointer(), "the report block is shared")
}

func TestPayload_EmptyAndAbsentResultListsStayAsTheyAre(t *testing.T) {
	empty := reportOf(t, KindVulnerabilityReport)

	assert.Equal(t, []any{}, entriesOf(t, Payload(empty, appWorkload), KindVulnerabilityReport), "[] stays []")

	absent := loadFixture(t, "vulnerabilityreport_replicaset.json")
	unstructured.RemoveNestedField(absent.Object, "report", "vulnerabilities")

	block, ok := Payload(absent, appWorkload)["report"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, block, "vulnerabilities", "an absent list stays absent")

	noBlock := loadFixture(t, "vulnerabilityreport_replicaset.json")
	unstructured.RemoveNestedField(noBlock.Object, "report")

	assert.NotContains(t, Payload(noBlock, appWorkload), "report")
}

func TestPayload_EntriesThatAreNotObjectsAreKept(t *testing.T) {
	report := reportOf(t, KindVulnerabilityReport, "x", "x", nil, nil)

	assert.Len(t, entriesOf(t, Payload(report, appWorkload), KindVulnerabilityReport), 4)
}

func TestPayload_DoesNotModifyTheReportBodyWhenItDropsEntries(t *testing.T) {
	report := reportOf(t, KindVulnerabilityReport, vulnEntry(), vulnEntry(), vulnEntry())

	before := report.DeepCopy()
	block, ok := report.Object["report"].(map[string]any)
	require.True(t, ok)

	payload := Payload(report, appWorkload)

	assert.Len(t, entriesOf(t, payload, KindVulnerabilityReport), 1)
	assert.Equal(t, before.Object, report.Object, "the report keeps its three entries")
	assert.Len(t, block["vulnerabilities"], 3)

	sentBlock, ok := payload["report"].(map[string]any)
	require.True(t, ok)

	sentBlock["added"] = true

	assert.NotContains(t, block, "added", "the sent report block is a copy")
}

// withNull returns a copy of the entry with the field present and null.
func withNull(entry map[string]any, field string) map[string]any {
	out := maps.Clone(entry)
	out[field] = nil

	return out
}

// Key parts follow the DefectDojo 3.5.200 Trivy Operator parser: an absent field is its default, a null field is
// "None"; the hash case-folds the parts.
func TestPayload_EntriesThatDefectDojoHashesEqualAreCollapsed(t *testing.T) {
	vuln, secret := vulnEntry(), secretEntry()

	for name, tc := range map[string]struct {
		kind string
		a, b map[string]any
	}{
		"vulnerability fixedVersion absent and null":     {KindVulnerabilityReport, with(vuln, "fixedVersion", nil), withNull(vuln, "fixedVersion")},
		"vulnerability fixedVersion absent and None":     {KindVulnerabilityReport, with(vuln, "fixedVersion", nil), with(vuln, "fixedVersion", "None")},
		"vulnerability title absent and null":            {KindVulnerabilityReport, with(vuln, "title", nil), withNull(vuln, "title")},
		"vulnerability title null and None":              {KindVulnerabilityReport, withNull(vuln, "title"), with(vuln, "title", "None")},
		"vulnerability resource absent and null":         {KindVulnerabilityReport, with(vuln, "resource", nil), withNull(vuln, "resource")},
		"vulnerability installedVersion absent and None": {KindVulnerabilityReport, with(vuln, "installedVersion", nil), with(vuln, "installedVersion", "None")},
		"vulnerability id absent and 0":                  {KindVulnerabilityReport, with(vuln, "vulnerabilityID", nil), with(vuln, "vulnerabilityID", "0")},
		"vulnerability id case":                          {KindVulnerabilityReport, vuln, with(vuln, "vulnerabilityID", "cve-2026-0001")},
		"vulnerability title case":                       {KindVulnerabilityReport, vuln, with(vuln, "title", "LIBSSL: OVERFLOW")},
		"vulnerability title case folding":               {KindVulnerabilityReport, with(vuln, "title", "Straße"), with(vuln, "title", "STRASSE")},
		"secret match absent and empty":                  {KindExposedSecretReport, with(secret, "match", nil), with(secret, "match", "")},
		"secret target absent and empty":                 {KindExposedSecretReport, with(secret, "target", nil), with(secret, "target", "")},
		"secret ruleID absent and 0":                     {KindExposedSecretReport, with(secret, "ruleID", nil), with(secret, "ruleID", "0")},
		"secret category absent and null":                {KindExposedSecretReport, with(secret, "category", nil), withNull(secret, "category")},
		"secret title null and None":                     {KindExposedSecretReport, withNull(secret, "title"), with(secret, "title", "None")},
		"secret match case":                              {KindExposedSecretReport, secret, with(secret, "match", "aws_access_key_id=****")},
	} {
		t.Run(name, func(t *testing.T) {
			report := reportOf(t, tc.kind, tc.a, tc.b)

			assert.Len(t, entriesOf(t, Payload(report, appWorkload), tc.kind), 1)
		})
	}
}

func TestPayload_EntriesThatDefectDojoHashesApartAreKept(t *testing.T) {
	vuln, secret := vulnEntry(), secretEntry()

	for name, tc := range map[string]struct {
		kind string
		a, b map[string]any
	}{
		"vulnerability fixedVersion absent and empty": {KindVulnerabilityReport, with(vuln, "fixedVersion", nil), with(vuln, "fixedVersion", "")},
		"vulnerability id absent and null":            {KindVulnerabilityReport, with(vuln, "vulnerabilityID", nil), withNull(vuln, "vulnerabilityID")},
		"vulnerability id absent and empty":           {KindVulnerabilityReport, with(vuln, "vulnerabilityID", nil), with(vuln, "vulnerabilityID", "")},
		"vulnerability id null and empty":             {KindVulnerabilityReport, withNull(vuln, "vulnerabilityID"), with(vuln, "vulnerabilityID", "")},
		"secret match null and empty":                 {KindExposedSecretReport, withNull(secret, "match"), with(secret, "match", "")},
		"secret category absent and empty":            {KindExposedSecretReport, with(secret, "category", nil), with(secret, "category", "")},
		"secret ruleID absent and empty":              {KindExposedSecretReport, with(secret, "ruleID", nil), with(secret, "ruleID", "")},
	} {
		t.Run(name, func(t *testing.T) {
			report := reportOf(t, tc.kind, tc.a, tc.b)

			assert.Len(t, entriesOf(t, Payload(report, appWorkload), tc.kind), 2)
		})
	}
}
