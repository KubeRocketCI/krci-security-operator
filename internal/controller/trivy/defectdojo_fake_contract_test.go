package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// The tests of this file check that the fake DefectDojo follows the DefectDojo 3.5.200 reimport contract.

const (
	contractService = "ns/Deployment/app/app"
	cveA            = "CVE-2026-0001 libssl 3.0.0"
	cveB            = "CVE-2026-0002 libssl 3.0.0"
)

type vuln struct {
	id, severity, fixed string
}

var (
	vulnA = vuln{id: "CVE-2026-0001", severity: "HIGH", fixed: "3.0.1"}
	vulnB = vuln{id: "CVE-2026-0002", severity: "LOW", fixed: "3.0.2"}
)

// appLabels are the Trivy Operator labels of the container app of the Deployment app in the namespace ns.
func appLabels() map[string]string {
	return map[string]string{
		trivy.LabelResourceNamespace: "ns",
		trivy.LabelResourceKind:      "Deployment",
		trivy.LabelResourceName:      "app",
		trivy.LabelContainerName:     "app",
	}
}

// vulnReport is a VulnerabilityReport of the package libssl 3.0.0 with the vulnerabilities.
func vulnReport(t *testing.T, labels map[string]string, vulns ...vuln) []byte {
	t.Helper()

	items := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		items = append(items, map[string]any{
			"vulnerabilityID":  v.id,
			"resource":         "libssl",
			"installedVersion": "3.0.0",
			"fixedVersion":     v.fixed,
			"severity":         v.severity,
			"title":            v.id + " in libssl",
		})
	}

	return marshalReport(t, labels, map[string]any{"vulnerabilities": items})
}

func marshalReport(t *testing.T, labels map[string]string, report map[string]any) []byte {
	t.Helper()

	doc := map[string]any{"kind": trivy.KindVulnerabilityReport, "metadata": map[string]any{"labels": labels}}
	if report != nil {
		doc["report"] = report
	}

	raw, err := json.Marshal(doc)
	require.NoError(t, err)

	return raw
}

func contractRequest(report []byte) defectdojo.ReimportRequest {
	return defectdojo.ReimportRequest{
		ProductType: "KubeRocketCI",
		Product:     "c/ns",
		Engagement:  "trivy-operator",
		TestTitle:   "VulnerabilityReport deployment/app/app",
		Service:     contractService,
		Version:     "1.0",
		Tags:        []string{"k8s-cluster:c"},
		Report:      report,
	}
}

func reimport(t *testing.T, f *fakeDefectDojo, r defectdojo.ReimportRequest) defectdojo.ReimportResult {
	t.Helper()

	res, err := f.Reimport(context.Background(), r)
	require.NoError(t, err)

	return res
}

func TestFakeDefectDojo_CreatesTheContextOnTheFirstReimport(t *testing.T) {
	f := newFakeDefectDojo()

	first := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA)))

	assert.Equal(t, ddContext{productType: "KubeRocketCI", product: "c/ns", engagement: "trivy-operator"},
		f.contextOf(first.TestID))

	again := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA)))
	assert.Equal(t, first, again, "the second reimport lands in the same test")

	other := contractRequest(vulnReport(t, appLabels(), vulnA))
	other.Product = "c/other"
	reimport(t, f, other)

	productTypes, products, engagements := f.counts()
	assert.Equal(t, 1, productTypes, "the product type is created once")
	assert.Equal(t, 2, products)
	assert.Equal(t, 2, engagements)
}

func TestFakeDefectDojo_FindsTheTestByEngagementScanTypeAndTitle(t *testing.T) {
	c := ddContext{productType: "KubeRocketCI", product: "c/ns", engagement: "trivy-operator"}

	f := newFakeDefectDojo()
	f.seedTestsIn(c, defectdojo.Test{ID: 1, Title: "VulnerabilityReport deployment/app/app"})
	f.seedTestsIn(c, defectdojo.Test{ID: 2, Title: "VulnerabilityReport deployment/app/app"})
	f.seedScanTest(c, "Trivy Scan", defectdojo.Test{ID: 3, Title: "VulnerabilityReport deployment/app/app"})

	assert.Equal(t, 2, reimport(t, f, contractRequest(vulnReport(t, appLabels()))).TestID,
		"the latest test with the scan type and the title")

	otherTitle := contractRequest(vulnReport(t, appLabels()))
	otherTitle.TestTitle = "ExposedSecretReport deployment/app/app"
	assert.Equal(t, firstTestID, reimport(t, f, otherTitle).TestID, "another title gets a new test")

	otherEngagement := contractRequest(vulnReport(t, appLabels()))
	otherEngagement.Engagement = "other"
	assert.Equal(t, firstTestID+1, reimport(t, f, otherEngagement).TestID, "another engagement gets a new test")
}

func TestFakeDefectDojo_RejectsAProductOfAnotherProductType(t *testing.T) {
	f := newFakeDefectDojo()
	f.seedTestsIn(ddContext{productType: "Other", product: "c/ns", engagement: "trivy-operator"},
		defectdojo.Test{ID: 1, Title: "VulnerabilityReport deployment/app/app"})

	_, err := f.Reimport(context.Background(), contractRequest(vulnReport(t, appLabels(), vulnA)))

	var apiErr *defectdojo.APIError

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	assert.Equal(t, []int{1}, f.testIDs(), "no test is created")

	productTypes, products, engagements := f.counts()
	assert.Equal(t, []int{1, 1, 1}, []int{productTypes, products, engagements}, "no product type, product or engagement is created")
}

func TestFakeDefectDojo_ParsesLikeTheTrivyOperatorParser(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.Service = ""

	found := f.findingsIn(reimport(t, f, r).TestID)

	require.Len(t, found, 1)
	assert.Equal(t, cveA, found[0].title)
	assert.Equal(t, "High", found[0].severity)
	assert.Equal(t, []string{"CVE-2026-0001"}, found[0].vulnIDs)
	assert.Equal(t, contractService, found[0].service, "the parser builds the service from the labels")
	assert.Equal(t, "CVE-2026-0001 in libssl\n**Fixed version:** 3.0.1\n\n**container.name:** app"+
		"\n**resource.kind:** Deployment\n**resource.name:** app\n**resource.namespace:** ns", found[0].description)
	assert.True(t, found[0].active)
	assert.False(t, found[0].verified)

	secrets := contractRequest(marshalReport(t, appLabels(), map[string]any{"secrets": []map[string]any{{
		"ruleID": "aws-access-key-id", "category": "AWS", "match": "AWS_ACCESS_KEY_ID=****",
		"severity": "CRITICAL", "target": "app/.env", "title": "AWS Access Key ID",
	}}}))
	secrets.TestTitle = "ExposedSecretReport deployment/app/app"

	found = f.findingsIn(reimport(t, f, secrets).TestID)

	require.Len(t, found, 1)
	assert.Equal(t, "Secret detected in app/.env - AWS Access Key ID", found[0].title)
	assert.Equal(t, "Critical", found[0].severity)
	assert.Empty(t, found[0].vulnIDs)
}

func TestFakeDefectDojo_ParserFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report func(t *testing.T) []byte
		status int
	}{
		{name: "invalid JSON", report: func(*testing.T) []byte { return []byte("{") }, status: http.StatusBadRequest},
		{
			name:   "unknown severity",
			report: func(t *testing.T) []byte { return vulnReport(t, appLabels(), vuln{id: "CVE-1", severity: "SEVERE"}) },
			status: http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDefectDojo()
			existing := contractRequest(vulnReport(t, appLabels(), vulnA))
			existing.TestTitle = "VulnerabilityReport deployment/existing/app"
			id := reimport(t, f, existing).TestID

			_, err := f.Reimport(context.Background(), contractRequest(tc.report(t)))

			var apiErr *defectdojo.APIError

			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, tc.status, apiErr.StatusCode)
			assert.Equal(t, []int{id, id + 1}, f.testIDs(), "the first reimport keeps the test it created before parsing")
			assert.Empty(t, f.findingsIn(id+1))

			existing.Report = tc.report(t)
			_, err = f.Reimport(context.Background(), existing)
			require.Error(t, err)
			assert.Equal(t, map[string]string{cveA: statusActive}, f.statuses(id, contractService),
				"a failed parse leaves an existing test unchanged")
		})
	}
}

func TestFakeDefectDojo_ReportWithoutLabelsOrResultListHasNoFindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report func(t *testing.T) []byte
	}{
		{name: "no labels", report: func(t *testing.T) []byte { return marshalReport(t, nil, map[string]any{}) }},
		{name: "no report block", report: func(t *testing.T) []byte { return marshalReport(t, appLabels(), nil) }},
		{name: "no result list", report: func(t *testing.T) []byte { return marshalReport(t, appLabels(), map[string]any{}) }},
		{name: "empty report", report: func(t *testing.T) []byte { return vulnReport(t, appLabels()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDefectDojo()
			id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnB))).TestID

			reimport(t, f, contractRequest(tc.report(t)))

			assert.Equal(t, map[string]string{cveA: statusClosed, cveB: statusClosed}, f.statuses(id, contractService),
				"zero findings close every finding of the service")
		})
	}
}

func TestFakeDefectDojo_FindingIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changed vuln
		same    bool
	}{
		{name: "same finding", changed: vulnA, same: true},
		{name: "case only", changed: vuln{id: "cve-2026-0001", severity: vulnA.severity, fixed: vulnA.fixed}, same: true},
		{name: "severity", changed: vuln{id: vulnA.id, severity: "CRITICAL", fixed: vulnA.fixed}},
		{name: "description", changed: vuln{id: vulnA.id, severity: vulnA.severity, fixed: "3.0.9"}},
		{name: "vulnerability id and title", changed: vuln{id: "CVE-2026-0009", severity: vulnA.severity, fixed: vulnA.fixed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDefectDojo()
			id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID
			before := f.findingsIn(id)

			reimport(t, f, contractRequest(vulnReport(t, appLabels(), tc.changed)))

			after := f.findingsIn(id)
			if tc.same {
				assert.Equal(t, before, after)

				return
			}

			require.Len(t, after, 2, "a new finding is created")
			assert.Equal(t, statusClosed, after[0].status(), "the old finding is closed")
			assert.Equal(t, statusActive, after[1].status())
		})
	}
}

func TestFakeDefectDojo_FirstUploadCreatesOneFindingPerEntry(t *testing.T) {
	f := newFakeDefectDojo()

	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnA, vulnB))).TestID

	found := f.findingsIn(id)

	require.Len(t, found, 3, "no matching on the upload that creates the test")
	assert.Equal(t, found[0].hash, found[1].hash)
	assert.NotEqual(t, found[0].hash, found[2].hash)

	for _, item := range found {
		assert.Equal(t, statusActive, item.status())
	}
}

func TestFakeDefectDojo_ReimportMatchesRepeatedEntriesToTheLowestFindingAndClosesTheOther(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnA, vulnB))).TestID

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnA, vulnB)))

	found := f.findingsIn(id)

	require.Len(t, found, 3)
	assert.Equal(t, statusActive, found[0].status(), "the lowest ID of the hash code stays")
	assert.Equal(t, statusClosed, found[1].status(), "no entry is left for the other finding")
	assert.Equal(t, statusActive, found[2].status())
}

func TestFakeDefectDojo_ClosedFindingOfARepeatedEntryStaysClosedWhileTheLowestOneFollowsTheReport(t *testing.T) {
	f := newFakeDefectDojo()
	repeated := vulnReport(t, appLabels(), vulnA, vulnA, vulnB)
	id := reimport(t, f, contractRequest(repeated)).TestID

	statuses := func() []string {
		out := make([]string, 0, 3)
		for _, item := range f.findingsIn(id) {
			out = append(out, item.status())
		}

		return out
	}

	reimport(t, f, contractRequest(repeated))
	assert.Equal(t, []string{statusActive, statusClosed, statusActive}, statuses(), "the second finding is closed")

	reimport(t, f, contractRequest(repeated))
	assert.Equal(t, []string{statusActive, statusClosed, statusActive}, statuses(), "the closed finding stays closed")

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnB)))
	assert.Equal(t, []string{statusClosed, statusClosed, statusActive}, statuses(), "the entry is gone: both are closed")

	reimport(t, f, contractRequest(repeated))
	assert.Equal(t, []string{statusActive, statusClosed, statusActive}, statuses(),
		"the entry is back: the lowest finding is reactivated, the other stays closed")
	assert.Len(t, f.findingsIn(id), 3, "no finding is created")
}

func TestFakeDefectDojo_ReimportCreatesOneFindingForAnEntryThatRepeatsInTheReport(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnB, vulnB)))

	assert.Equal(t, map[string]string{cveA: statusActive, cveB: statusActive}, f.statuses(id, contractService))
	assert.Len(t, f.findingsIn(id), 2, "the second entry matches the finding the first one created")
}

func TestFakeDefectDojo_RequestServiceReplacesTheParserService(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.Service = "a"

	id := reimport(t, f, r).TestID

	r.Service = "b"
	reimport(t, f, r)

	assert.Equal(t, map[string]string{cveA: statusActive}, f.statuses(id, "a"))
	assert.Equal(t, map[string]string{cveA: statusActive}, f.statuses(id, "b"),
		"the service is part of the identity: the same report under another service is a new finding")
	assert.Empty(t, f.statuses(id, contractService), "no finding keeps the parser service")
}

func TestFakeDefectDojo_ClosesOnlyFindingsOfTheRequestService(t *testing.T) {
	f := newFakeDefectDojo()
	a := contractRequest(vulnReport(t, appLabels(), vulnA, vulnB))
	a.Service = "a"
	id := reimport(t, f, a).TestID

	b := a
	b.Service = "b"
	reimport(t, f, b)

	a.Report = vulnReport(t, appLabels(), vulnA)
	reimport(t, f, a)

	assert.Equal(t, map[string]string{cveA: statusActive, cveB: statusClosed}, f.statuses(id, "a"))
	assert.Equal(t, map[string]string{cveA: statusActive, cveB: statusActive}, f.statuses(id, "b"),
		"findings of another service stay")
}

func TestFakeDefectDojo_WithoutServiceClosesOnlyFindingsWithoutService(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA, vulnB))
	r.Service = ""
	id := reimport(t, f, r).TestID
	f.seedFinding(id, "found by hand", "")

	r.Report = vulnReport(t, appLabels(), vulnA)
	reimport(t, f, r)

	assert.Equal(t, map[string]string{cveA: statusActive, cveB: statusActive}, f.statuses(id, contractService),
		"a finding with the parser service is not in the close set")
	assert.Equal(t, map[string]string{"found by hand": statusClosed}, f.statuses(id, ""))
}

func TestFakeDefectDojo_ReactivatesAClosedFindingTheReportHoldsAgain(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnB))).TestID
	before := f.findingsIn(id)

	closeTest(t, f, defectdojo.Test{ID: id})
	assert.Equal(t, map[string]string{cveA: statusClosed, cveB: statusClosed}, f.statuses(id, contractService))

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA)))

	after := f.findingsIn(id)
	require.Len(t, after, 2, "no new finding")
	assert.Equal(t, before[0].id, after[0].id)
	assert.Equal(t, map[string]string{cveA: statusActive, cveB: statusClosed}, f.statuses(id, contractService))
}

func TestFakeDefectDojo_KeepsTriageStates(t *testing.T) {
	cveC := "CVE-2026-0003 libssl 3.0.0"
	vulnC := vuln{id: "CVE-2026-0003", severity: "MEDIUM", fixed: "3.0.3"}

	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnB, vulnC))).TestID
	findings := f.findingsIn(id)

	f.triage(findings[0].id, statusFalsePositive)
	f.triage(findings[1].id, statusRiskAccepted)
	f.triage(findings[2].id, statusOutOfScope)

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnB, vulnC)))

	triaged := map[string]string{cveA: statusFalsePositive, cveB: statusRiskAccepted, cveC: statusOutOfScope}
	assert.Equal(t, triaged, f.statuses(id, contractService), "a matched finding keeps its triage state")

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnC)))

	assert.Equal(t, map[string]string{cveA: statusFalsePositive, cveB: statusClosed, cveC: statusOutOfScope},
		f.statuses(id, contractService), "a risk accepted finding missing from the report is closed")

	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnB)))
	reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnC)))

	for _, item := range f.findingsIn(id) {
		switch item.title {
		case cveA, cveC:
			assert.False(t, item.active, "a closed finding with a triage state is not reactivated: %s", item.title)
			assert.NotEqual(t, statusClosed, item.status(), "the triage state stays: %s", item.title)
		case cveB:
			assert.Equal(t, statusClosed, item.status(), "the finding without risk acceptance is closed again")
		}
	}
}

func TestFakeDefectDojo_WritesTheVersionAndReplacesTheTags(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels()))
	r.Tags = []string{"a:1", "b:2"}
	id := reimport(t, f, r).TestID

	test := f.test(id)
	assert.Equal(t, "1.0", test.version)
	assert.Equal(t, []string{"a:1", "b:2"}, test.tags)

	r.Version = ""
	r.Tags = []string{"c:3"}
	reimport(t, f, r)

	test = f.test(id)
	assert.Empty(t, test.version, "a missing version is written as empty")
	assert.Equal(t, []string{"c:3"}, test.tags, "the request tags replace the test tags")

	r.Tags = nil
	reimport(t, f, r)

	test = f.test(id)
	assert.Equal(t, []string{"c:3"}, test.tags, "a request without tags keeps the test tags")

	r.Version = " 2.0 "
	reimport(t, f, r)
	assert.Equal(t, "2.0", f.test(id).version, "a form value is stripped")

	r.Version = " "
	_, err := f.Reimport(context.Background(), r)

	var apiErr *defectdojo.APIError

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode, "a version of only whitespace is blank")
	assert.Equal(t, "2.0", f.test(id).version)
}

// closeTest closes the test through the fake and returns how it was closed.
func closeTest(t *testing.T, f *fakeDefectDojo, test defectdojo.Test) defectdojo.CloseResult {
	t.Helper()

	res, err := f.CloseTest(context.Background(), test)
	require.NoError(t, err)

	return res
}

// listedTest returns the test as the list of its engagement returns it.
func listedTest(t *testing.T, f *fakeDefectDojo, testID int) defectdojo.Test {
	t.Helper()

	ctx := context.Background()
	c := f.contextOf(testID)

	products, err := f.ListProductsByName(ctx, c.productType, c.product)
	require.NoError(t, err)
	require.Len(t, products, 1)

	tests, err := f.ListTests(ctx, products[0], c.engagement)
	require.NoError(t, err)

	for _, test := range tests {
		if test.ID == testID {
			return test
		}
	}

	require.Failf(t, "test not listed", "test %d", testID)

	return defectdojo.Test{}
}

func TestFakeDefectDojo_StoresTheBuildIDOfTheReimportAndListsIt(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels()))
	r.BuildID = "uid:100:0123456789ab"

	id := reimport(t, f, r).TestID

	assert.Equal(t, "uid:100:0123456789ab", f.test(id).buildID)
	assert.Equal(t, "uid:100:0123456789ab", listedTest(t, f, id).BuildID)

	r.BuildID = " uid:101:0123456789ab "
	reimport(t, f, r)
	assert.Equal(t, "uid:101:0123456789ab", f.test(id).buildID, "a reimport replaces it; a form value is stripped")

	r.BuildID = ""
	reimport(t, f, r)
	assert.Empty(t, f.test(id).buildID, "a reimport without a build_id writes an empty one")
	assert.Empty(t, listedTest(t, f, id).BuildID)
}

func TestFakeDefectDojo_RejectsABlankBuildID(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.BuildID = "uid:100:0123456789ab"
	id := reimport(t, f, r).TestID

	r.BuildID = "  "

	var apiErr *defectdojo.APIError

	_, err := f.Reimport(context.Background(), r)

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	assert.Contains(t, apiErr.Body, "build_id")
	assert.Equal(t, "uid:100:0123456789ab", f.test(id).buildID)
}

func TestFakeDefectDojo_BuildIDOverTheColumnLimitFailsAfterTheFindingsChanged(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID

	r := contractRequest(vulnReport(t, appLabels()))
	r.BuildID = strings.Repeat("é", 150)
	reimport(t, f, r)
	assert.Equal(t, strings.Repeat("é", 150), f.test(id).buildID, "150 characters fit")

	r.BuildID = strings.Repeat("é", 151)

	var apiErr *defectdojo.APIError

	_, err := f.Reimport(context.Background(), r)

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Equal(t, strings.Repeat("é", 150), f.test(id).buildID, "the test is not saved")
}

func TestFakeDefectDojo_CloseClearsTheBuildID(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.BuildID = "uid:100:0123456789ab"
	id := reimport(t, f, r).TestID

	closeTest(t, f, listedTest(t, f, id))

	assert.Empty(t, f.test(id).buildID)
	assert.Equal(t, 1, f.buildIDUpdates)
	assert.Equal(t, map[string]string{cveA: statusClosed}, f.statuses(id, contractService))
}

func TestFakeDefectDojo_CloseOfATestListedWithoutBuildIDUpdatesNothing(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID

	closeTest(t, f, listedTest(t, f, id))

	assert.Zero(t, f.buildIDUpdates)
}

func TestFakeDefectDojo_SetBuildIDWritesAndClearsIt(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID

	require.NoError(t, f.SetBuildID(context.Background(), id, "uid:100:0123456789ab"))
	assert.Equal(t, "uid:100:0123456789ab", f.test(id).buildID)
	assert.Equal(t, "uid:100:0123456789ab", listedTest(t, f, id).BuildID)

	require.NoError(t, f.SetBuildID(context.Background(), id, ""))
	assert.Empty(t, f.test(id).buildID)

	var apiErr *defectdojo.APIError

	require.ErrorAs(t, f.SetBuildID(context.Background(), id+1, "m"), &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}

func TestFakeDefectDojo_NewTestHasTheBuildIDWhenTheReportIsRejected(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest([]byte(`{`))
	r.BuildID = "uid:100:0123456789ab"

	var apiErr *defectdojo.APIError

	_, err := f.Reimport(context.Background(), r)

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	require.Len(t, f.testIDs(), 1, "DefectDojo creates the test before it reads the report")
	assert.Equal(t, "uid:100:0123456789ab", f.test(f.testIDs()[0]).buildID,
		"the build_id of a new test is saved with the test, before the findings")
	assert.Empty(t, f.findingsIn(f.testIDs()[0]))
}

func TestFakeDefectDojo_ExistingTestKeepsItsBuildIDWhenTheReportIsRejected(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.BuildID = "uid:100:0123456789ab"
	id := reimport(t, f, r).TestID

	r.BuildID = "uid:101:0123456789ab"
	r.Report = []byte(`{`)

	_, err := f.Reimport(context.Background(), r)

	require.Error(t, err)
	assert.Equal(t, "uid:100:0123456789ab", f.test(id).buildID, "the build_id of an existing test changes with its findings")
}

func TestFakeDefectDojo_NewTestWithABuildIDOverTheColumnLimitIsNotCreated(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.BuildID = strings.Repeat("é", 151)

	var apiErr *defectdojo.APIError

	_, err := f.Reimport(context.Background(), r)

	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Empty(t, f.testIDs())
}

// findingTitled returns the finding of the test with the title.
func findingTitled(t *testing.T, f *fakeDefectDojo, testID int, title string) ddFinding {
	t.Helper()

	for _, found := range f.findingsIn(testID) {
		if found.title == title {
			return found
		}
	}

	require.Failf(t, "finding not found", "title %q", title)

	return ddFinding{}
}

// TestFakeContract_Close* pin the close model of fakeDefectDojo.CloseTest, which the controller tests use in place of
// defectdojo.Client.CloseTest. They run the fake, not the client; a change to the client does not fail them.
// The request sequence of the client, and the answers it relies on, are tested against an HTTP server in
// pkg/defectdojo (TestClient_CloseTest_*).

func TestFakeContract_CloseMitigatesTheTriagedFindingsOfTheServiceToo(t *testing.T) {
	cveC := "CVE-2026-0003 libssl 3.0.0"
	cveD := "CVE-2026-0004 libssl 3.0.0"
	vulnC := vuln{id: "CVE-2026-0003", severity: "MEDIUM", fixed: "3.0.3"}
	vulnD := vuln{id: "CVE-2026-0004", severity: "LOW", fixed: "3.0.4"}

	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA, vulnB, vulnC, vulnD))).TestID
	findings := f.findingsIn(id)

	f.triage(findings[1].id, statusFalsePositive)
	f.triage(findings[2].id, statusRiskAccepted)
	f.triage(findings[3].id, statusOutOfScope)

	closeTest(t, f, listedTest(t, f, id))

	for _, title := range []string{cveA, cveB, cveC, cveD} {
		assert.True(t, findingTitled(t, f, id, title).isMitigated, "mitigated: %s", title)
		assert.False(t, findingTitled(t, f, id, title).active, "inactive: %s", title)
	}

	assert.True(t, findingTitled(t, f, id, cveB).falsePositive, "a false positive stays one")
	assert.True(t, findingTitled(t, f, id, cveD).outOfScope, "an out of scope finding stays one")
	assert.False(t, findingTitled(t, f, id, cveC).riskAccepted, "the risk acceptance is removed")
	assert.Equal(t, statusClosed, findingTitled(t, f, id, cveC).status())
}

func TestFakeContract_CloseOfATestWithoutActiveFindingsChangesNoFinding(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA, vulnB))
	r.BuildID = "uid:100:0123456789ab"
	id := reimport(t, f, r).TestID
	findings := f.findingsIn(id)

	f.triage(findings[0].id, statusFalsePositive)
	f.triage(findings[1].id, statusRiskAccepted)

	closeTest(t, f, listedTest(t, f, id))

	assert.Equal(t, map[string]string{cveA: statusFalsePositive, cveB: statusRiskAccepted},
		f.statuses(id, contractService), "no active finding: no reimport")
	assert.False(t, findingTitled(t, f, id, cveA).isMitigated)
	assert.True(t, findingTitled(t, f, id, cveB).riskAccepted)
	assert.Empty(t, f.test(id).buildID, "the marker is cleared")
}

func TestFakeContract_CloseReimportsEachServiceWithActiveFindings(t *testing.T) {
	f := newFakeDefectDojo()
	a := contractRequest(vulnReport(t, appLabels(), vulnA))
	a.Service = "a"
	id := reimport(t, f, a).TestID

	b := a
	b.Service = "b"
	b.Report = vulnReport(t, appLabels(), vulnA, vulnB)
	reimport(t, f, b)

	for _, item := range f.findingsIn(id) {
		if item.service == "b" && item.title == cveB {
			f.triage(item.id, statusFalsePositive)
		}
	}

	res := closeTest(t, f, listedTest(t, f, id))

	assert.Equal(t, defectdojo.CloseResult{Reimports: 2}, res)
	assert.Equal(t, map[string]string{cveA: statusClosed}, f.statuses(id, "a"))
	assert.Equal(t, map[string]string{cveA: statusClosed, cveB: statusFalsePositive}, f.statuses(id, "b"))
	assert.True(t, findingTitled(t, f, id, cveB).isMitigated, "the reimport of service b mitigates its false positive")
}

func TestFakeContract_CloseClosesOneByOneTheServicesBeyondTheBound(t *testing.T) {
	f := newFakeDefectDojo()

	var id int

	for i := range fakeCloseReimports + 1 {
		r := contractRequest(vulnReport(t, appLabels(), vulnA, vulnB))
		r.Service = fmt.Sprintf("s%d", i)
		id = reimport(t, f, r).TestID
	}

	for _, item := range f.findingsIn(id) {
		if item.service == fmt.Sprintf("s%d", fakeCloseReimports) && item.title == cveB {
			f.triage(item.id, statusFalsePositive)
		}
	}

	res := closeTest(t, f, listedTest(t, f, id))

	assert.Equal(t, defectdojo.CloseResult{Reimports: fakeCloseReimports, OneByOne: 1}, res)
	assert.Equal(t, map[string]string{cveA: statusClosed, cveB: statusFalsePositive},
		f.statuses(id, fmt.Sprintf("s%d", fakeCloseReimports)),
		"closing one by one touches only the active finding of the last service")
}

func TestFakeContract_CloseKeepsTheVersionAndTheTagsOfTheTest(t *testing.T) {
	f := newFakeDefectDojo()
	r := contractRequest(vulnReport(t, appLabels(), vulnA))
	r.Tags = []string{"a:1", "b:2"}
	r.Version = "2.0"
	id := reimport(t, f, r).TestID

	listed := listedTest(t, f, id)
	assert.Equal(t, "2.0", listed.Version)

	closeTest(t, f, listed)

	assert.Equal(t, "2.0", f.test(id).version, "the close sends the version of the listed test")
	assert.Equal(t, []string{"a:1", "b:2"}, f.test(id).tags)
}

func TestFakeContract_CloseWithoutTheVersionWritesAnEmptyOne(t *testing.T) {
	f := newFakeDefectDojo()
	id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID

	closeTest(t, f, defectdojo.Test{ID: id})

	assert.Empty(t, f.test(id).version, "a reimport without a version writes an empty one")
}

func TestFakeDefectDojo_NeverReusesATestID(t *testing.T) {
	f := newFakeDefectDojo()
	f.seedTests(defectdojo.Test{ID: 120, Title: "seeded"})

	first := reimport(t, f, contractRequest(vulnReport(t, appLabels()))).TestID
	assert.Equal(t, 121, first, "a new test gets an ID above the seeded ones")

	f.deleteTest(first)

	assert.Equal(t, 122, reimport(t, f, contractRequest(vulnReport(t, appLabels()))).TestID)
}

func TestFakeDefectDojo_ListsProductsByProductTypeAndName(t *testing.T) {
	ctx := context.Background()

	f := newFakeDefectDojo()
	f.seedNamespace("c", "ns", defectdojo.Test{ID: 1, Title: "a"})
	f.seedNamespace("x-c", "ns", defectdojo.Test{ID: 2, Title: "a"})
	f.seedNamespace("d", "ns", defectdojo.Test{ID: 3, Title: "a"})
	f.seedTestsIn(ddContext{productType: "Other", product: "c/other", engagement: "trivy-operator"},
		defectdojo.Test{ID: 4, Title: "a"})

	got, err := f.ListProducts(ctx, "KubeRocketCI", "C/")
	require.NoError(t, err)

	names := make([]string, 0, len(got))
	for _, p := range got {
		names = append(names, p.Name)
	}

	assert.Equal(t, []string{"c/ns", "x-c/ns"}, names,
		"the name matches by contains, case-insensitively, within the product type; the caller checks the prefix")

	_, err = f.ListProducts(ctx, "Missing", "c/")
	require.ErrorIs(t, err, defectdojo.ErrProductTypeNotFound)
}

func TestFakeDefectDojo_ListsProductsByExactName(t *testing.T) {
	ctx := context.Background()

	f := newFakeDefectDojo()
	f.seedNamespace("c", "kube", defectdojo.Test{ID: 1, Title: "a"})
	f.seedNamespace("c", "kube-system", defectdojo.Test{ID: 2, Title: "a"})
	f.seedNamespace("C", "kube", defectdojo.Test{ID: 3, Title: "a"})

	got, err := f.ListProductsByName(ctx, "KubeRocketCI", "c/kube")
	require.NoError(t, err)

	names := make([]string, 0, len(got))
	for _, p := range got {
		names = append(names, p.Name)
	}

	assert.Equal(t, []string{"c/kube", "C/kube"}, names, "the whole name matches, case-insensitively")

	_, err = f.ListProductsByName(ctx, "Missing", "c/kube")
	require.ErrorIs(t, err, defectdojo.ErrProductTypeNotFound)
}

func TestFakeDefectDojo_ListsTestsOfTheEngagementByScanType(t *testing.T) {
	ctx := context.Background()
	c := namespaceContext("c", "ns")

	f := newFakeDefectDojo()
	f.seedTestsIn(c, defectdojo.Test{ID: 7, Title: "a"}, defectdojo.Test{ID: 3, Title: "b"})
	f.seedScanTest(c, "Trivy Scan", defectdojo.Test{ID: 5, Title: "c"})
	f.seedTestsIn(ddContext{productType: c.productType, product: c.product, engagement: "other"},
		defectdojo.Test{ID: 6, Title: "d"})
	f.seedNamespace("c", "ns2", defectdojo.Test{ID: 8, Title: "e"})

	products, err := f.ListProducts(ctx, "KubeRocketCI", "c/ns")
	require.NoError(t, err)
	require.Len(t, products, 2)

	tests, err := f.ListTests(ctx, products[0], "trivy-operator")
	require.NoError(t, err)

	require.Len(t, tests, 2)
	assert.Equal(t, []int{3, 7}, []int{tests[0].ID, tests[1].ID}, "ordered by ID; no other scan type, engagement or product")
	assert.Equal(t, "c/ns", tests[0].Product)
	assert.Equal(t, defectdojo.ScanTypeTrivyOperator, tests[0].ScanType)
}

func TestFakeDefectDojo_PatchReplacesTheProductTags(t *testing.T) {
	ctx := context.Background()

	f := newFakeDefectDojo()
	f.seedNamespace("c", "ns", defectdojo.Test{ID: 1, Title: "a"})
	f.seedProductTags("c/ns", "owner:team", "k8s-cluster:old")

	products, err := f.ListProducts(ctx, "KubeRocketCI", "c/ns")
	require.NoError(t, err)
	require.Len(t, products, 1)
	assert.Equal(t, []string{"owner:team", "k8s-cluster:old"}, products[0].Tags)

	require.NoError(t, f.SetProductTags(ctx, products[0].ID, []string{"k8s-cluster:c"}))
	assert.Equal(t, []string{"k8s-cluster:c"}, f.productTags("c/ns"), "a PATCH replaces the list")

	var apiErr *defectdojo.APIError

	require.ErrorAs(t, f.SetProductTags(ctx, 99, nil), &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
}

func TestFakeDefectDojo_ValidatesTagsLikeTheTagListSerializerField(t *testing.T) {
	for name, tag := range map[string]string{
		"space":        "a b:1",
		"comma":        "a,b:1",
		"single quote": "a'b:1",
		"double quote": `a"b:1`,
		"over 255":     "a:" + strings.Repeat("é", 254),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeDefectDojo()
			id := reimport(t, f, contractRequest(vulnReport(t, appLabels(), vulnA))).TestID

			r := contractRequest(vulnReport(t, appLabels(), vulnA))
			r.Tags = []string{"k:1", tag}

			var apiErr *defectdojo.APIError

			_, err := f.Reimport(context.Background(), r)

			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
			assert.Contains(t, apiErr.Body, "tags")
			assert.Equal(t, []string{"k8s-cluster:c"}, f.test(id).tags, "a rejected request changes nothing")
		})
	}

	t.Run("a tag of 255 characters is stored lower case", func(t *testing.T) {
		f := newFakeDefectDojo()
		r := contractRequest(vulnReport(t, appLabels(), vulnA))
		r.Tags = []string{"K8s-Cluster:" + strings.Repeat("É", 255-len("k8s-cluster:"))}

		id := reimport(t, f, r).TestID

		assert.Equal(t, []string{"k8s-cluster:" + strings.Repeat("é", 255-len("k8s-cluster:"))}, f.test(id).tags)
	})
}

func TestFakeDefectDojo_RejectsValuesOverTheFieldLimits(t *testing.T) {
	tests := map[string]struct {
		set   func(*defectdojo.ReimportRequest, string)
		limit int
	}{
		"service":      {set: func(r *defectdojo.ReimportRequest, v string) { r.Service = v }, limit: 200},
		"version":      {set: func(r *defectdojo.ReimportRequest, v string) { r.Version = v }, limit: 100},
		"test_title":   {set: func(r *defectdojo.ReimportRequest, v string) { r.TestTitle = v }, limit: 255},
		"product_name": {set: func(r *defectdojo.ReimportRequest, v string) { r.Product = v }, limit: 255},
	}

	for field, tt := range tests {
		t.Run(field, func(t *testing.T) {
			f := newFakeDefectDojo()
			r := contractRequest(vulnReport(t, appLabels(), vulnA))

			tt.set(&r, strings.Repeat("é", tt.limit))
			reimport(t, f, r)

			tt.set(&r, strings.Repeat("é", tt.limit+1))

			var apiErr *defectdojo.APIError

			_, err := f.Reimport(context.Background(), r)

			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
			assert.Contains(t, apiErr.Body, field)
		})
	}
}
