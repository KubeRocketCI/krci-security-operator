package trivy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	tenantKey = "app.edp.epam.com/tenant"
	// The label tags of the labels of these tests.
	tenantTag      = "app.edp.epam.com/tenant:krci-demo-dev"
	otherTenantTag = "app.edp.epam.com/tenant:other"
	oldTenantTag   = "app.edp.epam.com/tenant:old"
	envTag         = "env:dev"
	teamTag        = "team:payments"
	// ownCluster and ownNamespace are the tags of the namespace product of the go app that no label gives.
	ownCluster   = "k8s-cluster:in-cluster"
	ownNamespace = "k8s-namespace:krci-demo-dev"

	// vulnerabilityMarker and secretMarker are the upload markers of the two reports of the go app, as the operator
	// wrote them before the label tags existed.
	vulnerabilityMarker = "uid-vulnerabilityreport_replicaset.json:100:7294de6cb9ee"
	secretMarker        = "uid-exposedsecretreport_replicaset.json:100:9eeaa82bef32"
)

// markersWithoutLabelTags are the upload markers of the tests of the go app by title.
var markersWithoutLabelTags = map[string]string{goAppTitle: vulnerabilityMarker, secretsTitle: secretMarker}

// productTagsWith returns the tags of the namespace product of the go app with the label tags.
func productTagsWith(labelTags ...string) []string {
	return append([]string{ownCluster, ownNamespace}, labelTags...)
}

// testTagsOf returns the tags of the test of the go app of the report kind, as the operator wrote them before the
// label tags existed, with the label tags.
func testTagsOf(reportKind string, labelTags ...string) []string {
	return append([]string{
		ownCluster, ownNamespace, "k8s-workload:deployment.test-go-app",
		"k8s-container:test-go-app", "oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app",
		"report-kind:" + reportKind,
	}, labelTags...)
}

// labelSettings are the two label allow-lists and the labels they are applied to.
type labelSettings struct {
	namespaceKeys, workloadKeys     []string
	namespaceLabels, workloadLabels map[string]string
}

// labelled is the go app, its vulnerability report and its exposed secret report, with the settings.
func labelled(t *testing.T, s labelSettings) *harness {
	t.Helper()

	objects := goAppObjects()
	objects[goAppNamespace] = namespaceObject(appNS, s.namespaceLabels)

	deploy, ok := objects[goAppDeployment].(*appsv1.Deployment)
	require.True(t, ok)

	deploy.Labels = s.workloadLabels

	h := newHarness(t, withReports(objects, goApp(t), goAppSecrets(t)))
	h.reconciler.config.NamespaceLabelTags = s.namespaceKeys
	h.reconciler.config.WorkloadLabelTags = s.workloadKeys

	return h
}

// relabelNamespace replaces the labels of the namespace of the go app.
func (h *harness) relabelNamespace(labels map[string]string) {
	h.t.Helper()

	h.update(namespaceObject(appNS, labels))
}

// relabelWorkload replaces the labels of the Deployment of the go app.
func (h *harness) relabelWorkload(labels map[string]string) {
	h.t.Helper()

	deploy := &appsv1.Deployment{}
	require.NoError(h.t, h.client.Get(h.t.Context(), client.ObjectKey{Namespace: appNS, Name: "test-go-app"}, deploy))

	deploy.Labels = labels
	require.NoError(h.t, h.client.Update(h.t.Context(), deploy))
}

// testIDOf returns the ID of the test with the title.
func (h *harness) testIDOf(title string) int {
	h.t.Helper()

	for _, id := range h.dd.testIDs() {
		if h.dd.test(id).title == title {
			return id
		}
	}

	h.t.Fatalf("DefectDojo holds no test %q", title)

	return 0
}

// storedTags returns the tags DefectDojo holds on the test with the title.
func (h *harness) storedTags(title string) []string { return h.dd.test(h.testIDOf(title)).tags }

// markers returns the upload markers of the tests by title.
func (h *harness) markers() map[string]string {
	out := map[string]string{}

	for _, id := range h.dd.testIDs() {
		out[h.dd.test(id).title] = h.markerOf(id)
	}

	return out
}

func TestReconcile_NamespaceLabelTagsGoToTheProductOnly(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey, "env", "absent"},
		namespaceLabels: map[string]string{tenantKey: appNS, "env": "Dev", "unlisted": "x"},
	})

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.ElementsMatch(t, productTagsWith(tenantTag, envTag), h.dd.productTags(goAppProduct))
	assert.ElementsMatch(t, testTagsOf("vulnerabilityreport"), h.storedTags(goAppTitle), "no namespace label tag on a test")
	assert.ElementsMatch(t, testTagsOf("exposedsecretreport"), h.storedTags(secretsTitle))
	assert.Equal(t, markersWithoutLabelTags, h.markers(),
		"a namespace label is not part of the request of a test")
}

func TestReconcile_WorkloadLabelTagsGoToTheTestsOnly(t *testing.T) {
	h := labelled(t, labelSettings{
		workloadKeys:    []string{"team", "absent"},
		workloadLabels:  map[string]string{"team": "Payments", "unlisted": "x"},
		namespaceLabels: map[string]string{"team": "of-the-namespace"},
	})

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)
	assert.ElementsMatch(t, testTagsOf("vulnerabilityreport", teamTag), h.storedTags(goAppTitle))
	assert.ElementsMatch(t, testTagsOf("exposedsecretreport", teamTag), h.storedTags(secretsTitle))
	assert.ElementsMatch(t, productTagsWith(), h.dd.productTags(goAppProduct), "no workload label tag on the product")
}

func TestReconcile_AWorkloadLabelIsReadFromTheTopWorkloadObject(t *testing.T) {
	objects := goAppObjects()

	rs, ok := objects[goAppDeployment+1].(*appsv1.ReplicaSet)
	require.True(t, ok)

	rs.Labels = map[string]string{"team": "of-the-replicaset"}

	deploy, ok := objects[goAppDeployment].(*appsv1.Deployment)
	require.True(t, ok)

	deploy.Labels = map[string]string{"team": "of-the-deployment"}

	h := newHarness(t, withReports(objects, goApp(t)))
	h.reconciler.config.WorkloadLabelTags = []string{"team"}

	h.reconcile()

	assert.Contains(t, h.storedTags(goAppTitle), "team:of-the-deployment")
	assert.NotContains(t, h.storedTags(goAppTitle), "team:of-the-replicaset")
}

func TestReconcile_AnAbsentLabelGivesNoTag(t *testing.T) {
	for name, s := range map[string]labelSettings{
		"the labels are not on the objects": {
			namespaceKeys: []string{tenantKey}, workloadKeys: []string{"team"},
			namespaceLabels: map[string]string{"unlisted": "x"}, workloadLabels: map[string]string{"unlisted": "x"},
		},
		"the labels have an empty value": {
			namespaceKeys: []string{tenantKey}, workloadKeys: []string{"team"},
			namespaceLabels: map[string]string{tenantKey: ""}, workloadLabels: map[string]string{"team": ""},
		},
		"the objects have no label": {namespaceKeys: []string{tenantKey}, workloadKeys: []string{"team"}},
		"no key is listed": {
			namespaceLabels: map[string]string{tenantKey: appNS}, workloadLabels: map[string]string{"team": "payments"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := labelled(t, s)

			h.reconcile()

			require.Len(t, h.dd.reimports, 2)
			assert.ElementsMatch(t, productTagsWith(), h.dd.productTags(goAppProduct))
			assert.ElementsMatch(t, testTagsOf("vulnerabilityreport"), h.storedTags(goAppTitle))
			assert.ElementsMatch(t, testTagsOf("exposedsecretreport"), h.storedTags(secretsTitle))
			assert.Equal(t, markersWithoutLabelTags, h.markers(),
				"the upload markers are those of the operator without the settings")
			assert.Len(t, h.dd.tagCalls, 1, "the product is patched once, for its two tags")

			h.restart()
			h.reconcile()

			assert.Len(t, h.dd.reimports, 2, "an unchanged namespace is not uploaded again")
			assert.Len(t, h.dd.tagCalls, 1)
		})
	}
}

func TestReconcile_ALongLabelValueIsShortenedByTheRuleOfEveryTag(t *testing.T) {
	long := strings.Repeat("v", 300)
	h := labelled(t, labelSettings{
		namespaceKeys: []string{"team"}, workloadKeys: []string{"owner"},
		namespaceLabels: map[string]string{"team": long}, workloadLabels: map[string]string{"owner": long},
	})

	require.NoError(t, h.reconcileErr(), "a tag over 255 characters fails the save of a test in DefectDojo")

	wantProduct := "team:" + trivy.Shorten(long, trivy.MaxTagLen-len("team:"))
	wantTest := "owner:" + trivy.Shorten(long, trivy.MaxTagLen-len("owner:"))

	assert.Contains(t, h.dd.productTags(goAppProduct), wantProduct)
	assert.Contains(t, h.storedTags(goAppTitle), wantTest)
	assert.Len(t, wantProduct, trivy.MaxTagLen)
	assert.Len(t, wantTest, trivy.MaxTagLen)
	assert.Contains(t, wantTest, "~", "the start of the value, the sign and a hash")
}

func TestReconcile_ALabelValueIsMadeTagSafe(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys: []string{"Env"}, workloadKeys: []string{"Team.Name"},
		namespaceLabels: map[string]string{"Env": "Prod EU"}, workloadLabels: map[string]string{"Team.Name": "A, B"},
	})

	h.reconcile()

	assert.Contains(t, h.dd.productTags(goAppProduct), "env:prod-eu", "the key and the value are in lower case")
	assert.Contains(t, h.storedTags(goAppTitle), "team.name:a--b")

	tagCalls := len(h.dd.tagCalls)

	h.reconcile()

	assert.Len(t, h.dd.tagCalls, tagCalls, "the tags the operator wrote are the tags it wants: no patch on the next pass")
}

func TestReconcile_ALabelChangeReachesTheProductOnTheNextPass(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey},
		namespaceLabels: map[string]string{tenantKey: appNS, "unlisted": "x"},
	})

	h.reconcile()
	require.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))

	h.relabelNamespace(map[string]string{tenantKey: "other", "unlisted": "x"})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(otherTenantTag), h.dd.productTags(goAppProduct), "a changed label")

	h.relabelNamespace(map[string]string{"unlisted": "x"})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(), h.dd.productTags(goAppProduct), "a removed label")

	h.relabelNamespace(map[string]string{tenantKey: appNS})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct), "a label that returns")
	assert.Len(t, h.dd.reimports, 2, "a namespace label is not part of the request of a test: no upload")

	tagCalls := len(h.dd.tagCalls)

	h.relabelNamespace(map[string]string{tenantKey: appNS, "unlisted": "changed"})
	h.reconcile()

	assert.Len(t, h.dd.tagCalls, tagCalls, "a label that is not listed changes nothing")
}

func TestReconcile_AProductKeepsItsTagsOfKeysThatAreNotListedAndOwnsTheListedKeys(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey},
		namespaceLabels: map[string]string{tenantKey: appNS},
	})
	h.dd.seedTests(ownedTest(100, goAppTitle))
	h.dd.seedProductTags(goAppProduct, "owner:payments", oldTenantTag, "app.edp.epam.com/tenant:older", "env:prod",
		"app.edp.epam.com/tenant-name:x", "k8s-namespace:old")

	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(tenantTag, "owner:payments", "env:prod", "app.edp.epam.com/tenant-name:x"),
		h.dd.productTags(goAppProduct),
		"the tags of the listed key are replaced by the one of the label, every other tag stays")
	require.Len(t, h.dd.tagCalls, 1)

	h.reconcile()

	assert.Len(t, h.dd.tagCalls, 1, "a product that has its tags is not patched again")
}

func TestReconcile_AKeyThatLeavesTheListLeavesItsTagsOnTheProduct(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey, "env"},
		namespaceLabels: map[string]string{tenantKey: appNS, "env": "dev"},
	})

	h.reconcile()
	require.ElementsMatch(t, productTagsWith(tenantTag, envTag), h.dd.productTags(goAppProduct))

	h.reconciler.config.NamespaceLabelTags = []string{tenantKey}
	h.relabelNamespace(map[string]string{tenantKey: "other", "env": "prod"})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(otherTenantTag, envTag), h.dd.productTags(goAppProduct),
		"the tag of the key that is no longer listed is neither corrected nor removed")

	h.reconciler.config.NamespaceLabelTags = nil
	h.relabelNamespace(nil)
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(otherTenantTag, envTag), h.dd.productTags(goAppProduct),
		"with no key listed the operator keeps every label tag")
}

func TestReconcile_AChangedWorkloadListUploadsEveryTestOnce(t *testing.T) {
	h := labelled(t, labelSettings{workloadLabels: map[string]string{"team": "Payments", "tier": "backend"}})

	h.reconcile()
	require.Len(t, h.dd.reimports, 2)
	require.Equal(t, markersWithoutLabelTags, h.markers())

	h.reconciler.config.WorkloadLabelTags = []string{"team"}
	h.reconcile()

	require.Len(t, h.dd.reimports, 4, "both tests are uploaded again with the new tag")
	assert.ElementsMatch(t, testTagsOf("vulnerabilityreport", teamTag), h.storedTags(goAppTitle))
	assert.ElementsMatch(t, testTagsOf("exposedsecretreport", teamTag), h.storedTags(secretsTitle))
	assert.NotEqual(t, vulnerabilityMarker, h.markers()[goAppTitle])
	assert.NotEqual(t, secretMarker, h.markers()[secretsTitle])

	h.reconcile()
	h.restart()
	h.reconcile()

	assert.Len(t, h.dd.reimports, 4, "the next pass and a restart upload nothing: the marker names the request")

	h.reconciler.config.WorkloadLabelTags = []string{"team", "tier", "absent"}
	h.reconcile()

	require.Len(t, h.dd.reimports, 6, "another key whose label exists changes the request")
	assert.Contains(t, h.storedTags(goAppTitle), "tier:backend")

	h.reconciler.config.WorkloadLabelTags = []string{"team", "tier", "absent", "other-absent"}
	h.reconcile()

	assert.Len(t, h.dd.reimports, 6, "a key without a label changes nothing")

	h.reconciler.config.WorkloadLabelTags = nil
	h.reconcile()

	require.Len(t, h.dd.reimports, 8, "an emptied list uploads every test once")
	assert.ElementsMatch(t, testTagsOf("vulnerabilityreport"), h.storedTags(goAppTitle))
	assert.Equal(t, markersWithoutLabelTags, h.markers(),
		"the upload markers are those of the operator without the setting")
}

func TestReconcile_AChangedWorkloadLabelUploadsTheTestsOfTheWorkloadOnce(t *testing.T) {
	h := labelled(t, labelSettings{
		workloadKeys: []string{"team"}, workloadLabels: map[string]string{"team": "payments"},
	})

	h.reconcile()
	require.Len(t, h.dd.reimports, 2)

	h.relabelWorkload(map[string]string{"team": "billing"})
	h.reconcile()

	require.Len(t, h.dd.reimports, 4, "the reports did not change; their tags did")
	assert.ElementsMatch(t, testTagsOf("vulnerabilityreport", "team:billing"), h.storedTags(goAppTitle))

	h.relabelWorkload(nil)
	h.reconcile()

	require.Len(t, h.dd.reimports, 6)
	assert.ElementsMatch(t, testTagsOf("vulnerabilityreport"), h.storedTags(goAppTitle), "a removed label removes its tag")

	h.reconcile()

	assert.Len(t, h.dd.reimports, 6)
}

func TestReconcile_AGoneOrExcludedNamespaceKeepsTheLabelTagsAndRepairsTheOthers(t *testing.T) {
	for how, leave := range leavingNamespace {
		t.Run(how, func(t *testing.T) {
			h := labelled(t, labelSettings{
				namespaceKeys:   []string{tenantKey},
				namespaceLabels: map[string]string{tenantKey: appNS},
			})
			h.reconcile()
			require.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))

			testID := h.testIDOf(goAppTitle)

			leave(h)
			h.dd.seedProductTags(goAppProduct, tenantTag, "owner:payments", "k8s-namespace:old")
			h.reconcile()

			assert.Equal(t, bothClosed, h.dd.statuses(testID, goAppService))
			assert.ElementsMatch(t, productTagsWith(tenantTag, "owner:payments"), h.dd.productTags(goAppProduct),
				"the label tag stays, the two product tags are repaired")
		})
	}
}

func TestReconcile_AnExcludedNamespaceDoesNotFollowItsLabelsAndAReturningOneGetsTheCurrentTags(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey},
		namespaceLabels: map[string]string{tenantKey: appNS},
	})
	h.reconcile()

	h.reconciler.config.ExcludeNamespaces = []string{appNS}
	h.relabelNamespace(map[string]string{tenantKey: "other"})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct), "the tags of the last import")

	h.reconciler.config.ExcludeNamespaces = nil
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(otherTenantTag), h.dd.productTags(goAppProduct))
}

func TestReconcile_AFailedUpdateOfTheLabelTagsOfTheProductIsRetried(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey},
		namespaceLabels: map[string]string{tenantKey: appNS},
	})
	h.dd.tagErr = &defectdojo.APIError{StatusCode: 500}

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.productTags(goAppProduct))

	h.dd.tagErr = nil

	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))
}

func TestSweep_WakesAnImportedNamespaceOnlyForItsTwoProductTags(t *testing.T) {
	h := labelled(t, labelSettings{
		namespaceKeys:   []string{tenantKey},
		namespaceLabels: map[string]string{tenantKey: appNS},
	})
	h.reconcile()
	require.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))

	require.NoError(t, h.reconciler.sweep(t.Context()))
	assert.Empty(t, wakes(h), "a product with its tags and a label tag is not woken")

	h.dd.seedProductTags(goAppProduct, tenantTag, "k8s-namespace:old")
	require.NoError(t, h.reconciler.sweep(t.Context()))

	assert.Equal(t, []string{appNS}, wakes(h))
}
