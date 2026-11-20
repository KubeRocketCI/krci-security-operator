package trivy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// goAppImage is the image of the report of the go app.
var goAppImage = trivy.Image{
	Name:   "gitlab.127.0.0.1.nip.io:5050/krci/test-go-app",
	Tag:    "main-20261110-194848",
	Digest: "sha256:9155b03ee4d94b88f7ef3632b86417509c8d75bce88edc6c5c2b01eaf266a9c9",
}

// bodiesOver returns reportBodies over a cluster that holds the objects, with known as the facts of earlier passes,
// and the names of the reports it reads with a GET.
func bodiesOver(
	t *testing.T,
	known map[reportVersion]versionFacts,
	objects ...client.Object,
) (*reportBodies, client.Client, *[]string) {
	t.Helper()

	var gets []string

	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			gets = append(gets, key.Name)

			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()

	lookup := func(v reportVersion) (versionFacts, bool) {
		f, ok := known[v]

		return f, ok
	}

	return newReportBodies(c, appNS, lookup), c, &gets
}

// metaOf returns the record of a report as a listing gives it.
func metaOf(report *unstructured.Unstructured) reportMeta {
	return reportMeta{kind: report.GetKind(), obj: metadataOf(report.GetKind(), report)}
}

// stored returns the report as the cluster holds it.
func stored(t *testing.T, c client.Client, report *unstructured.Unstructured) *unstructured.Unstructured {
	t.Helper()

	out := &unstructured.Unstructured{}
	out.SetGroupVersionKind(report.GroupVersionKind())
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(report), out))

	return out
}

// storedMeta returns the record of the report as the cluster holds it, and resets the GETs counted so far.
func storedMeta(t *testing.T, c client.Client, report *unstructured.Unstructured, gets *[]string) reportMeta {
	t.Helper()

	m := metaOf(stored(t, c, report))
	*gets = nil

	return m
}

func TestReportBodies_KnownVersionIsNotRead(t *testing.T) {
	report := goApp(t)
	known := map[reportVersion]versionFacts{
		{uid: "uid-vulnerabilityreport_replicaset.json", resourceVersion: "100"}: {
			kind: trivy.KindVulnerabilityReport, image: trivy.Image{Name: "remembered"},
		},
	}

	b, _, gets := bodiesOver(t, known)

	f, read, body, err := b.facts(context.Background(), metaOf(report))

	require.NoError(t, err)
	assert.Equal(t, sameVersion, read)
	assert.Nil(t, body)
	assert.Equal(t, trivy.Image{Name: "remembered"}, f.image)
	assert.Empty(t, *gets)
}

func TestReportBodies_UnknownVersionIsReadOnceInThePass(t *testing.T) {
	b, c, gets := bodiesOver(t, nil, goApp(t))
	m := storedMeta(t, c, goApp(t), gets)

	f, read, body, err := b.facts(context.Background(), m)

	require.NoError(t, err)
	assert.Equal(t, sameVersion, read)
	require.NotNil(t, body)
	assert.Equal(t, "replicaset-test-go-app-9dc66c9c6-test-go-app", body.GetName())
	assert.Equal(t, versionFacts{kind: trivy.KindVulnerabilityReport, image: goAppImage}, f)

	again, read, body, err := b.facts(context.Background(), m)

	require.NoError(t, err)
	assert.Equal(t, sameVersion, read)
	assert.Nil(t, body, "a version read in the pass is not read again")
	assert.Equal(t, f, again)
	assert.Equal(t, []string{"replicaset-test-go-app-9dc66c9c6-test-go-app"}, *gets)
}

func TestReportBodies_GoneReportHasNoFacts(t *testing.T) {
	b, _, gets := bodiesOver(t, nil)
	m := metaOf(goApp(t))

	f, read, body, err := b.facts(context.Background(), m)

	require.NoError(t, err)
	assert.Equal(t, gone, read)
	assert.Nil(t, body)
	assert.Equal(t, versionFacts{}, f)
	assert.Empty(t, b.read)
	assert.Len(t, *gets, 1)
}

func TestReportBodies_OtherVersionHasTheFactsOfTheReadVersion(t *testing.T) {
	for name, listed := range map[string]func(*unstructured.Unstructured) *unstructured.Unstructured{
		"other resourceVersion": func(r *unstructured.Unstructured) *unstructured.Unstructured {
			r.SetResourceVersion("1")

			return r
		},
		"other UID under the same name": func(r *unstructured.Unstructured) *unstructured.Unstructured {
			r.SetUID("uid-deleted")

			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, c, gets := bodiesOver(t, nil, goApp(t))
			current := stored(t, c, goApp(t))
			m := metaOf(listed(current.DeepCopy()))
			*gets = nil

			f, read, body, err := b.facts(context.Background(), m)

			require.NoError(t, err)
			assert.Equal(t, otherVersion, read)
			require.NotNil(t, body)
			assert.Equal(t, versionOf(current), versionOf(body))
			assert.Equal(t, versionFacts{kind: trivy.KindVulnerabilityReport, image: goAppImage}, f)
			assert.Contains(t, b.read, versionOf(current), "the facts are recorded under the read version")
			assert.NotContains(t, b.read, versionOf(m.obj))
			assert.Len(t, *gets, 1)
		})
	}
}

func TestReportBodies_BrokenBodyIsAFact(t *testing.T) {
	broken := withoutField(t, goApp(t), "report", "vulnerabilities")
	b, c, _ := bodiesOver(t, nil, broken)

	f, read, _, err := b.facts(context.Background(), metaOf(stored(t, c, broken)))

	require.NoError(t, err)
	assert.Equal(t, sameVersion, read)
	assert.Equal(t, "no report.vulnerabilities list", f.broken)
}

func TestReportBodies_ReadFailureFailsThePass(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return k8sErrors.NewServiceUnavailable("down")
		},
	}).Build()
	b := newReportBodies(c, appNS, func(reportVersion) (versionFacts, bool) { return versionFacts{}, false })

	_, _, body, err := b.facts(context.Background(), metaOf(goApp(t)))

	require.Error(t, err)
	assert.True(t, k8sErrors.IsServiceUnavailable(err))
	assert.Nil(t, body)
}

func TestReportBodies_BodyForComparesTheVersion(t *testing.T) {
	known := map[reportVersion]versionFacts{
		{uid: "uid-vulnerabilityreport_replicaset.json", resourceVersion: "100"}: {kind: trivy.KindVulnerabilityReport},
	}

	t.Run("same version", func(t *testing.T) {
		b, c, gets := bodiesOver(t, known, goApp(t))
		m := storedMeta(t, c, goApp(t), gets)

		body, read, err := b.bodyFor(context.Background(), m)

		require.NoError(t, err)
		assert.Equal(t, sameVersion, read)
		require.NotNil(t, body)
		assert.Len(t, *gets, 1, "a known version is read for its upload")
	})

	t.Run("other version", func(t *testing.T) {
		b, c, _ := bodiesOver(t, known, goApp(t))
		listed := stored(t, c, goApp(t))
		listed.SetResourceVersion("1")

		body, read, err := b.bodyFor(context.Background(), metaOf(listed))

		require.NoError(t, err)
		assert.Equal(t, otherVersion, read)
		require.NotNil(t, body)
		assert.NotEqual(t, "1", body.GetResourceVersion())
	})

	t.Run("gone", func(t *testing.T) {
		b, _, _ := bodiesOver(t, known)

		body, read, err := b.bodyFor(context.Background(), metaOf(goApp(t)))

		require.NoError(t, err)
		assert.Equal(t, gone, read)
		assert.Nil(t, body)
	})
}

// named returns a report of the container key ReplicaSet web-rs/app, named name.
func named(t *testing.T, name string) *unstructured.Unstructured {
	t.Helper()

	r := kindsOfWorkload()["Deployment"].report(t, "web", appContainer)
	r.SetName(name)
	r.SetUID(types.UID("uid-" + name))

	return r
}

var webRS = containerKey{kind: "replicaset", name: "web-rs", container: appContainer}

// target is the target of the namespace of the go app, which has no labels.
func (h *harness) target() trivy.Target { return h.reconciler.target(namespaceObject(appNS, nil)) }

func TestListReports_SortsByNameAndIndexesInNameOrder(t *testing.T) {
	expired := named(t, "b-expired")
	expired.SetAnnotations(map[string]string{trivy.AnnotationReportTTL: "0s"})

	h := newHarness(t, withReports(base(), named(t, "c-report"), expired, named(t, "a-report")), descendingReports())
	p := &pass{target: h.target(), reports: newReportListing()}

	listed, err := h.reconciler.listReports(context.Background(), p, trivy.KindVulnerabilityReport)

	require.NoError(t, err)
	assert.True(t, listed)
	assert.Equal(t, []string{"a-report", "b-expired", "c-report"}, p.reports.worklist[trivy.KindVulnerabilityReport])
	assert.Equal(t, []string{"a-report", "c-report"}, p.reports.candidates(trivy.KindVulnerabilityReport, webRS),
		"an expired report is not indexed")
}

func TestListReports_RestartedListingKeepsNoRecordOfItsEarlierPages(t *testing.T) {
	listings := 0

	h := newHarness(t, withReports(base(), named(t, "a-report"), named(t, "b-report")), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)

			if !isReportListOf(list, trivy.KindVulnerabilityReport) {
				return c.List(ctx, list, opts...)
			}

			if lo.Continue != "" {
				return errExpired
			}

			listings++

			meta := list.(*metav1.PartialObjectMetadataList)
			if err := c.List(ctx, meta, client.InNamespace(appNS)); err != nil {
				return err
			}

			if listings == 1 {
				meta.SetContinue("page-2")

				return nil
			}

			meta.Items = meta.Items[1:]

			return nil
		},
	})
	h.unwatch()

	p := &pass{target: h.target(), reports: newReportListing()}

	listed, err := h.reconciler.listReports(context.Background(), p, trivy.KindVulnerabilityReport)

	require.NoError(t, err)
	assert.True(t, listed)
	assert.Equal(t, []string{"b-report"}, p.reports.worklist[trivy.KindVulnerabilityReport])
	assert.Equal(t, []string{"b-report"}, p.reports.candidates(trivy.KindVulnerabilityReport, webRS))
}

func TestListReports_FailedListingLeavesNoRecords(t *testing.T) {
	h := newHarness(t, withReports(base(), named(t, "a-report")), failMetadataOfReports(errors.New("down")))
	p := &pass{target: h.target(), reports: newReportListing()}

	listed, err := h.reconciler.listReports(context.Background(), p, trivy.KindVulnerabilityReport)

	require.Error(t, err)
	assert.False(t, listed)
	assert.Empty(t, p.reports.records)
}

func TestReportListing_AdoptWritesNewIndexSlices(t *testing.T) {
	l := newReportListing()
	for _, name := range []string{"a-report", "b-report", "c-report"} {
		l.add(trivy.KindVulnerabilityReport, metaOf(named(t, name)).obj)
	}

	l.finish(trivy.KindVulnerabilityReport)

	held := l.candidates(trivy.KindVulnerabilityReport, webRS)
	require.Equal(t, []string{"a-report", "b-report", "c-report"}, held)

	moved := named(t, "b-report")
	moved.SetLabels(map[string]string{
		trivy.LabelResourceKind: "ReplicaSet", trivy.LabelResourceName: "web-rs", trivy.LabelContainerName: sidecarContainer,
	})
	moved.SetResourceVersion("101")

	l.adopt(trivy.KindVulnerabilityReport, "b-report", otherVersion, moved)
	l.adopt(trivy.KindVulnerabilityReport, "a-report", gone, nil)

	assert.Equal(t, []string{"a-report", "b-report", "c-report"}, held, "a slice handed out is never changed")
	assert.Equal(t, []string{"c-report"}, l.candidates(trivy.KindVulnerabilityReport, webRS))
	assert.Equal(t, []string{"b-report"}, l.candidates(trivy.KindVulnerabilityReport,
		containerKey{kind: "replicaset", name: "web-rs", container: sidecarContainer}))

	rec, ok := l.record(trivy.KindVulnerabilityReport, "b-report")
	require.True(t, ok)
	assert.Equal(t, "101", rec.obj.GetResourceVersion(), "the read version is the effective version")

	_, ok = l.record(trivy.KindVulnerabilityReport, "a-report")
	assert.False(t, ok)
	assert.Equal(t, []string{"a-report", "b-report", "c-report"}, l.worklist[trivy.KindVulnerabilityReport],
		"the worklist keeps the names")
}
