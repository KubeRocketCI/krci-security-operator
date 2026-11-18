package trivy

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const ignoredReportMessage = "Ignored a report of a test that has another current report"

// ownAndReplicaSetReports are the report on the Deployment web and the report on its current ReplicaSet, both of
// the container app.
func ownAndReplicaSetReports(t *testing.T) (objects []client.Object, own, onReplicaSet *unstructured.Unstructured) {
	t.Helper()

	deployments := kindsOfWorkload()["Deployment"]

	return append(base(), deployments.objects("web", appContainer)...),
		kindOfWorkload{resourceKind: "Deployment", resource: ownName}.report(t, "web", appContainer),
		deployments.report(t, "web", appContainer)
}

func logCount(logged, message string) int { return strings.Count(logged, message) }

// A workload name over 63 characters is not a valid label value: Trivy Operator writes it to the annotation only.
func TestReconcile_OwnReportOfAWorkloadWithALongNameIsChosenWhateverTheListOrder(t *testing.T) {
	name := strings.Repeat("w", 240)
	replicaSetName := name + "-9dc66c9c6"

	objects := []client.Object{
		integrationSecret(), namespaceObject(appNS, nil), deployment(name, "1", appContainer), replicaSet(replicaSetName, name, "1"),
	}

	named := func(report, resourceKind, resource string) *unstructured.Unstructured {
		r := goApp(t)
		r.SetName(report)
		r.SetUID(types.UID("uid-" + report))
		r.SetLabels(map[string]string{
			trivy.LabelResourceKind:      resourceKind,
			trivy.LabelResourceNamespace: appNS,
			trivy.LabelContainerName:     appContainer,
		})
		r.SetAnnotations(map[string]string{trivy.LabelResourceName: resource})

		return r
	}

	own := named("a-deployment", "Deployment", name)
	onReplicaSet := named("b-replicaset", "ReplicaSet", replicaSetName)

	for order, funcs := range map[string][]interceptor.Funcs{
		"ascending":  nil,
		"descending": {descendingReports()},
	} {
		t.Run(order, func(t *testing.T) {
			h := newHarness(t, withReports(objects, onReplicaSet, own), funcs...)

			logged := h.reconcileLogged()

			require.Len(t, h.dd.reimports, 1, "one report is uploaded")
			assert.Equal(t, own.GetName(), reportNameOf(t, h.dd.reimports[0]), "the report on the Deployment comes first")
			assert.Equal(t, 1, logCount(logged, ignoredReportMessage), "the report that loses is logged once")

			h.reconcile()

			assert.Len(t, h.dd.reimports, 1)
		})
	}
}

func TestReconcile_ReportThatLosesIsLoggedOncePerPass(t *testing.T) {
	objects, own, onReplicaSet := ownAndReplicaSetReports(t)

	for order, funcs := range map[string][]interceptor.Funcs{
		"ascending":  nil,
		"descending": {descendingReports()},
	} {
		t.Run(order, func(t *testing.T) {
			h := newHarness(t, withReports(objects, own, onReplicaSet), funcs...)

			logged := h.reconcileLogged()

			assert.Equal(t, 1, logCount(logged, ignoredReportMessage))
			assert.Equal(t, 1, logCount(logged, onReplicaSet.GetName()))
		})
	}
}

func TestReconcile_OwnReportThatCannotBeUploadedDoesNotHideTheReportOfAReplicaSet(t *testing.T) {
	deleted := func(r *unstructured.Unstructured) {
		r.SetFinalizers([]string{"test/hold"})
		r.SetDeletionTimestamp(&metav1.Time{Time: scanDate})
	}

	for name, spoil := range map[string]func(*unstructured.Unstructured){
		"report of the Deployment is marked for deletion": deleted,
		"report of the Deployment is broken": func(r *unstructured.Unstructured) {
			unstructured.RemoveNestedField(r.Object, "report")
		},
		"report of the Deployment expires": func(r *unstructured.Unstructured) {
			r.SetAnnotations(map[string]string{trivy.AnnotationReportTTL: "0s"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			objects, own, onReplicaSet := ownAndReplicaSetReports(t)
			spoil(own)

			for order, funcs := range map[string][]interceptor.Funcs{
				"ascending":  nil,
				"descending": {descendingReports()},
			} {
				h := newHarness(t, withReports(objects, own, onReplicaSet), funcs...)

				logged := h.reconcileLogged()
				h.reconcile()

				require.Len(t, h.dd.reimports, 1, order)
				assert.Equal(t, onReplicaSet.GetName(), reportNameOf(t, h.dd.reimports[0]), order)
				assert.Zero(t, logCount(logged, ignoredReportMessage), order, "no current report is ignored")
			}
		})
	}
}

func TestReconcile_RejectedOwnReportDoesNotHideTheReportOfAReplicaSet(t *testing.T) {
	objects, own, onReplicaSet := ownAndReplicaSetReports(t)

	h := newHarness(t, withReports(objects, own, onReplicaSet))
	h.dd.reimportErr = func(r defectdojo.ReimportRequest) error {
		if reportNameOf(t, r) == own.GetName() {
			return &defectdojo.APIError{StatusCode: 400}
		}

		return nil
	}

	for range 4 {
		h.reconcile()
	}

	uploaded := make([]string, 0, len(h.dd.reimports))
	for _, r := range h.dd.reimports {
		uploaded = append(uploaded, reportNameOf(t, r))
	}

	assert.Equal(t, []string{own.GetName(), onReplicaSet.GetName()}, uploaded,
		"the rejected version is not uploaded again, and the report of the ReplicaSet is used once it is known")
	assert.NotZero(t, h.activeFindingsOf(kindsOfWorkload()["Deployment"].title("web", appContainer)))
}

func TestReconcile_OwnReportOfAnotherContainerDoesNotHideTheReportOfAReplicaSet(t *testing.T) {
	deployments := kindsOfWorkload()["Deployment"]
	objects := append(base(), deployments.objects("web", appContainer, sidecarContainer)...)

	onReplicaSet := deployments.report(t, "web", appContainer)
	ownSidecar := kindOfWorkload{resourceKind: "Deployment", resource: ownName}.report(t, "web", sidecarContainer)

	h := newHarness(t, withReports(objects, onReplicaSet, ownSidecar))

	logged := h.reconcileLogged()

	require.Len(t, h.dd.reimports, 2)
	assert.ElementsMatch(t, []string{onReplicaSet.GetName(), ownSidecar.GetName()},
		[]string{reportNameOf(t, h.dd.reimports[0]), reportNameOf(t, h.dd.reimports[1])})
	assert.Zero(t, logCount(logged, ignoredReportMessage))
}

// failMetadataOfReports makes the list of the metadata of the reports fail with err.
func failMetadataOfReports(err error) interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if l, ok := list.(*metav1.PartialObjectMetadataList); ok && l.GroupVersionKind().Group == trivy.TrivyGroup {
				return err
			}

			return c.List(ctx, list, opts...)
		},
	}
}

func TestReconcile_MetadataListOfReportsFailureStopsThePass(t *testing.T) {
	objects, own, onReplicaSet := ownAndReplicaSetReports(t)

	// The report of the ReplicaSet is read first, so the pass has to look for the report on the Deployment.
	onReplicaSet.SetName("a-" + onReplicaSet.GetName())

	h := newHarness(t, withReports(objects, own, onReplicaSet), failMetadataOfReports(assert.AnError))
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport deployment/removed/removed"))

	err := h.reconcileErr()

	require.ErrorIs(t, err, assert.AnError)
	assert.Empty(t, h.dd.closed, "a pass that cannot decide between two reports closes nothing")
	assert.Empty(t, h.dd.reimports, "the report that may lose is not uploaded")
}

func TestReconcile_ReportKindThatIsNotServedForMetadataHasNoOwnReport(t *testing.T) {
	objects, _, onReplicaSet := ownAndReplicaSetReports(t)
	noMatch := &meta.NoKindMatchError{
		GroupKind:        schema.GroupKind{Group: trivy.TrivyGroup, Kind: trivy.KindVulnerabilityReport},
		SearchedVersions: []string{trivy.TrivyVersion},
	}

	h := newHarness(t, withReports(objects, onReplicaSet), failMetadataOfReports(noMatch))

	h.reconcile()

	require.Len(t, h.dd.reimports, 1)
	assert.Equal(t, onReplicaSet.GetName(), reportNameOf(t, h.dd.reimports[0]))
}

func TestReconcile_OwnReportsAreListedOncePerKindAndPass(t *testing.T) {
	objects, own, _ := ownAndReplicaSetReports(t)
	deployments := kindsOfWorkload()["Deployment"]

	reports := make([]*unstructured.Unstructured, 0, 4)
	reports = append(reports, own)

	for _, name := range []string{"a", "b", "c"} {
		objects = append(objects, deployment(name, "1", appContainer), replicaSet(name+"-rs", name, "1"))
		reports = append(reports, deployments.report(t, name, appContainer))
	}

	lists := 0
	counting := interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if l, ok := list.(*metav1.PartialObjectMetadataList); ok && l.GroupVersionKind().Group == trivy.TrivyGroup {
				lists++
			}

			return c.List(ctx, list, opts...)
		},
	}

	h := newHarness(t, withReports(objects, reports...), counting)

	h.reconcile()

	require.Len(t, h.dd.reimports, 4, "the report on web and the report of each ReplicaSet with no report on its Deployment")
	assert.Equal(t, 1, lists, "one metadata list serves every report of the kind")
}

// pageOfDeployments serves the Deployments one at a time through continue tokens, and fails every page after the
// first with a 410 from the second listing on.
func pageOfDeployments() interceptor.Funcs {
	firstPages := 0

	return interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			deployments, ok := list.(*appsv1.DeploymentList)
			if !ok {
				return c.List(ctx, list, opts...)
			}

			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)

			if lo.Continue == "" {
				firstPages++
			} else if firstPages > 1 {
				return k8sErrors.NewResourceExpired("the continue token is too old")
			}

			if err := c.List(ctx, deployments, opts...); err != nil {
				return err
			}

			all := deployments.Items
			from, _ := strconv.Atoi(lo.Continue)
			to := min(from+1, len(all))
			deployments.Items = all[from:to]

			if to < len(all) {
				deployments.SetContinue(strconv.Itoa(to))
			}

			return nil
		},
	}
}

func TestReconcile_FailureOnALaterPageOfWorkloadsClosesNothing(t *testing.T) {
	objects := append(goAppObjects(), deployment("other", "1"), deployment("third", "1"))

	h := newHarness(t, withReports(objects, goApp(t)), pageOfDeployments())
	h.dd.seedTests(ownedTest(7, "VulnerabilityReport deployment/removed/removed"))

	err := h.reconcileErr()

	require.Error(t, err)
	assert.True(t, k8sErrors.IsResourceExpired(err), "the failure of the second page of the close-time list is returned")
	assert.Empty(t, h.dd.closed, "workloads that cannot be listed completely are not workloads that are gone")
}
