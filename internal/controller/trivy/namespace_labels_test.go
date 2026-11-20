package trivy

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	tenantKey = "example.com/tenant"
	// The label tags of the labels of these tests.
	tenantTag      = "k8s-ns-label.example.com/tenant:krci"
	otherTenantTag = "k8s-ns-label.example.com/tenant:other"
	oldTenantTag   = "k8s-ns-label.example.com/tenant:old"
	envTag         = "k8s-ns-label.env:dev"
	// ownCluster and ownNamespace are the tags of the namespace product of the go app that no label gives.
	ownCluster   = "k8s-cluster:in-cluster"
	ownNamespace = "k8s-namespace:krci-demo-dev"
)

// productTagsWith returns the tags of the namespace product of the go app with the label tags.
func productTagsWith(labelTags ...string) []string {
	return append([]string{ownCluster, ownNamespace}, labelTags...)
}

// labelTagsIn returns the namespace label tags among the tags.
func labelTagsIn(tags []string) []string {
	return slices.DeleteFunc(slices.Clone(tags), func(t string) bool {
		return !strings.HasPrefix(t, trivy.TagPrefixNamespaceLabel)
	})
}

// labelledObjects is goAppObjects with the labels on the namespace.
func labelledObjects(labels map[string]string) []client.Object {
	objects := goAppObjects()
	objects[goAppNamespace] = namespaceObject(appNS, labels)

	return objects
}

// labelledHarness is the go app in a namespace with the labels, with the keys listed in the setting.
func labelledHarness(t *testing.T, labels map[string]string, keys ...string) *harness {
	t.Helper()

	h := newHarness(t, withReports(labelledObjects(labels), goApp(t)))
	h.reconciler.config.NamespaceLabelTags = keys

	return h
}

// relabel replaces the labels of the namespace of the go app.
func (h *harness) relabel(labels map[string]string) {
	h.t.Helper()

	h.update(namespaceObject(appNS, labels))
}

// testTags returns the tags DefectDojo holds on the test.
func (h *harness) testTags(testID int) []string { return h.dd.test(testID).tags }

func TestReconcile_NamespaceLabelTagsGoToTheProductAndEveryTestOfTheNamespace(t *testing.T) {
	h := newHarness(t, withReports(labelledObjects(map[string]string{
		tenantKey: "krci", "env": "Dev Team", "unlisted": "x",
	}), goApp(t), goAppSecrets(t)))
	h.reconciler.config.NamespaceLabelTags = []string{tenantKey, "env", "absent"}

	h.reconcile()

	require.Len(t, h.dd.reimports, 2)

	for _, title := range []string{goAppTitle, secretsTitle} {
		assert.Equal(t, []string{tenantTag, "k8s-ns-label.env:dev-team"}, labelTagsIn(h.byTitle()[title].Tags),
			title+": the listed labels that the namespace has")
	}

	assert.Equal(t, []string{
		ownCluster, ownNamespace, tenantTag, "k8s-ns-label.env:dev-team",
		"k8s-workload:deployment.test-go-app", "k8s-container:test-go-app",
		"oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app",
	}, h.byTitle()[goAppTitle].Tags)

	assert.ElementsMatch(t, productTagsWith(tenantTag, "k8s-ns-label.env:dev-team"), h.dd.productTags(goAppProduct))

	for _, id := range h.dd.testIDs() {
		assert.Contains(t, h.testTags(id), tenantTag, "the tags DefectDojo stores")
	}
}

func TestReconcile_WithoutAListedLabelTheRequestsAreThoseWithoutLabelTags(t *testing.T) {
	plain := newHarness(t, withReports(goAppObjects(), goApp(t), goAppSecrets(t)))
	plain.reconcile()

	require.Len(t, plain.dd.reimports, 2)

	for name, tc := range map[string]struct {
		labels map[string]string
		keys   []string
	}{
		"no key is listed":                     {labels: map[string]string{tenantKey: "krci", "env": "dev"}},
		"the namespace lacks the listed label": {labels: map[string]string{"unlisted": "x"}, keys: []string{tenantKey}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, withReports(labelledObjects(tc.labels), goApp(t), goAppSecrets(t)))
			h.reconciler.config.NamespaceLabelTags = tc.keys

			h.reconcile()

			assert.Equal(t, plain.dd.reimports, h.dd.reimports, "the whole request: tags, version, upload marker")
			assert.Equal(t, plain.dd.productTags(goAppProduct), h.dd.productTags(goAppProduct))
			assert.Equal(t, plain.dd.tagCalls, h.dd.tagCalls)

			for i, id := range plain.dd.testIDs() {
				assert.Equal(t, plain.markerOf(id), h.markerOf(h.dd.testIDs()[i]), "the upload marker")
				assert.Equal(t, plain.testTags(id), h.testTags(h.dd.testIDs()[i]))
			}

			assert.ElementsMatch(t, productTagsWith(), h.dd.productTags(goAppProduct))
			assert.Empty(t, labelTagsIn(h.dd.reimports[0].Tags))

			h.restart()
			h.reconcile()

			assert.Len(t, h.dd.reimports, 2, "an unchanged namespace is not uploaded again")
		})
	}
}

func TestReconcile_ALabelChangeReachesDefectDojoOnTheNextPass(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci", "unlisted": "x"}, tenantKey)
	testID := h.onlyTest()
	marker := h.markerOf(testID)

	require.Contains(t, h.dd.productTags(goAppProduct), tenantTag)

	h.relabel(map[string]string{tenantKey: "other", "unlisted": "x"})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(otherTenantTag), h.dd.productTags(goAppProduct), "the product tag is corrected")
	require.Len(t, h.dd.reimports, 2, "the report is uploaded with the new tag")
	assert.Contains(t, h.dd.reimports[1].Tags, otherTenantTag)
	assert.NotContains(t, h.testTags(testID), tenantTag)
	assert.Contains(t, h.testTags(testID), otherTenantTag)
	assert.NotEqual(t, marker, h.markerOf(testID))

	h.relabel(map[string]string{"unlisted": "x"})
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(), h.dd.productTags(goAppProduct), "a removed label removes its tag")
	require.Len(t, h.dd.reimports, 3)
	assert.Equal(t, []string{
		ownCluster, ownNamespace, "k8s-workload:deployment.test-go-app",
		"k8s-container:test-go-app", "oci-image:gitlab.127.0.0.1.nip.io:5050/krci/test-go-app",
	}, h.dd.reimports[2].Tags)

	tagCalls, uploads := len(h.dd.tagCalls), len(h.dd.reimports)

	h.relabel(map[string]string{"unlisted": "changed"})
	h.reconcile()

	assert.Len(t, h.dd.tagCalls, tagCalls, "a label that is not listed changes nothing")
	assert.Len(t, h.dd.reimports, uploads)
}

func TestReconcile_ProductTagsOfLabelsKeepTheOtherTagsAndOwnThePrefix(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci"}, tenantKey)
	h.dd.seedTests(ownedTest(100, goAppTitle))
	h.dd.seedProductTags(goAppProduct, "owner:payments", oldTenantTag, "k8s-ns-label.stale:x", "k8s-namespace:old")

	h.reconcile()

	assert.ElementsMatch(t, append(productTagsWith(tenantTag), "owner:payments"), h.dd.productTags(goAppProduct),
		"a foreign tag stays, a wrong value is corrected, a tag of a key not listed is removed")
	require.Len(t, h.dd.tagCalls, 1)

	h.reconcile()

	assert.Len(t, h.dd.tagCalls, 1, "a product that has its tags is not patched again")
}

func TestReconcile_EnablingAndDisablingTheSettingUploadsEveryReportOnce(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci"})
	testID := h.onlyTest()
	plainMarker := h.markerOf(testID)
	plainRequest := h.dd.reimports[0]

	h.reconciler.config.NamespaceLabelTags = []string{tenantKey}
	h.restart()
	h.reconcile()

	require.Len(t, h.dd.reimports, 2, "enabling the setting uploads the report once")
	assert.NotEqual(t, plainMarker, h.markerOf(testID))
	assert.Contains(t, h.dd.reimports[1].Tags, tenantTag)
	assert.NotEmpty(t, h.dd.reimports[1].BuildID, "the marker goes with the reimport of an existing test")
	assert.Contains(t, h.testTags(testID), tenantTag)
	assert.Contains(t, h.dd.productTags(goAppProduct), tenantTag)

	enabledMarker := h.markerOf(testID)

	h.restart()
	h.reconcile()

	assert.Len(t, h.dd.reimports, 2, "the marker names the request: no upload after a restart")
	assert.Equal(t, enabledMarker, h.markerOf(testID))

	h.reconciler.config.NamespaceLabelTags = nil
	h.restart()
	h.reconcile()

	require.Len(t, h.dd.reimports, 3, "disabling the setting uploads the report once")
	assert.Equal(t, plainMarker, h.markerOf(testID), "the marker is the one of the operator without label tags")
	assert.Equal(t, plainRequest.Tags, h.dd.reimports[2].Tags)
	assert.NotContains(t, h.testTags(testID), tenantTag)
	assert.ElementsMatch(t, productTagsWith(), h.dd.productTags(goAppProduct), "the product tag of the label is removed")
}

func TestReconcile_GoneOrExcludedNamespaceKeepsTheLabelTagsOfTheKeysStillListed(t *testing.T) {
	for name, tc := range map[string]struct {
		keys, left []string
		want       []string
	}{
		"the keys stay listed":  {keys: []string{tenantKey, "env"}, left: []string{tenantKey, "env"}, want: productTagsWith(tenantTag, envTag)},
		"a key leaves the list": {keys: []string{tenantKey, "env"}, left: []string{tenantKey}, want: productTagsWith(tenantTag)},
		"no key is listed":      {keys: []string{tenantKey, "env"}, want: productTagsWith()},
	} {
		for how, leave := range leavingNamespace {
			t.Run(how+", "+name, func(t *testing.T) {
				h := labelledHarness(t, map[string]string{tenantKey: "krci", "env": "dev"}, tc.keys...)
				testID := importedGoApp(t, h)
				require.ElementsMatch(t, productTagsWith(tenantTag, envTag), h.dd.productTags(goAppProduct))

				h.reconciler.config.NamespaceLabelTags = tc.left

				leave(h)
				h.reconcile()

				assert.Equal(t, bothClosed, h.dd.statuses(testID, goAppService))
				assert.ElementsMatch(t, tc.want, h.dd.productTags(goAppProduct))
			})
		}
	}
}

func TestReconcile_ReturningNamespaceGetsTheCurrentLabelTags(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci"}, tenantKey)
	importedGoApp(t, h)

	h.reconciler.config.ExcludeNamespaces = []string{appNS}
	h.relabel(map[string]string{tenantKey: "other"})
	h.reconcile()

	assert.Contains(t, h.dd.productTags(goAppProduct), tenantTag, "an excluded namespace keeps the tags of its last pass")

	h.reconciler.config.ExcludeNamespaces = nil
	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(otherTenantTag), h.dd.productTags(goAppProduct))
}

func TestReconcile_FailedLabelTagUpdateIsRetried(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci"}, tenantKey)
	h.dd.tagErr = &defectdojo.APIError{StatusCode: 500}

	require.Error(t, h.reconcileErr())
	assert.Empty(t, h.dd.productTags(goAppProduct))

	h.dd.tagErr = nil

	h.reconcile()

	assert.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))
}

func TestSweep_WakesALiveNamespaceWhoseProductHasWrongLabelTags(t *testing.T) {
	for name, have := range map[string][]string{
		"another value":    productTagsWith(oldTenantTag),
		"no label tag":     productTagsWith(),
		"a tag not listed": productTagsWith(tenantTag, "k8s-ns-label.stale:x"),
	} {
		t.Run(name, func(t *testing.T) {
			h := labelledHarness(t, map[string]string{tenantKey: "krci"}, tenantKey)
			h.reconcile()
			require.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))

			require.NoError(t, h.reconciler.sweep(context.Background()))
			require.Empty(t, wakes(h), "a product with the right tags is not woken")

			h.dd.seedProductTags(goAppProduct, have...)
			calls := len(h.dd.tagCalls)

			require.NoError(t, h.reconciler.sweep(context.Background()))

			assert.Equal(t, []string{appNS}, wakes(h))
			assert.Len(t, h.dd.tagCalls, calls, "the sweeper writes nothing")

			h.reconcile()

			assert.ElementsMatch(t, productTagsWith(tenantTag), h.dd.productTags(goAppProduct))
		})
	}
}

func TestSweep_WakesALiveNamespaceWhoseProductKeepsLabelTagsOfADisabledSetting(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci"}, tenantKey)
	h.reconcile()

	h.reconciler.config.NamespaceLabelTags = nil

	require.NoError(t, h.reconciler.sweep(context.Background()))
	assert.Equal(t, []string{appNS}, wakes(h))
}

func TestSweep_WakesAReleasedNamespaceWhoseProductKeepsTheTagOfAKeyThatLeftTheList(t *testing.T) {
	h := labelledHarness(t, map[string]string{tenantKey: "krci", "env": "dev"}, tenantKey, "env")
	importedGoApp(t, h)

	h.remove(namespaceObject(appNS, nil))
	h.reconcile()

	require.NoError(t, h.reconciler.sweep(context.Background()))
	require.Empty(t, wakes(h), "the keys are the same")

	h.reconciler.config.NamespaceLabelTags = []string{tenantKey}

	require.NoError(t, h.reconciler.sweep(context.Background()))
	assert.Equal(t, []string{appNS}, wakes(h))
}
