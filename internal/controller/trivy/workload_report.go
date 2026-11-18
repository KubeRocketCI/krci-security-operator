package trivy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// reportMetadataPageSize is the number of report metadata objects read per list call.
const reportMetadataPageSize = 500

// containerKey identifies the reports of one container of a resource: the resource kind in lower case, its name and the
// container.
type containerKey struct {
	kind      string
	name      string
	container string
}

// indexedReport is a report that is neither marked for deletion nor expired, as far as its metadata tells.
type indexedReport struct {
	name    string
	version reportVersion
}

// workloadReport returns the name of the workload report that names the same test as a report of one of its
// ReplicaSets or Jobs and that can be uploaded, or "" when there is none or the report is a workload report itself.
// The report on a ReplicaSet or Job is not uploaded then, whichever of the two the listing delivers first.
// A report that is marked for deletion, expired, broken or of a held rejected version does not count.
func (r *Reconciler) workloadReport(
	ctx context.Context,
	p *pass,
	key testKey,
	report *unstructured.Unstructured,
	workload trivy.Workload,
) (string, error) {
	if namesWorkload(report, workload) {
		return "", nil
	}

	index, err := r.reportsOfKind(ctx, p, report.GetKind())
	if err != nil {
		return "", err
	}

	candidates := index[containerKey{
		kind:      workload.Kind,
		name:      workload.Name,
		container: trivy.ContainerOf(report),
	}]

	slices.SortFunc(candidates, func(a, b indexedReport) int { return strings.Compare(a.name, b.name) })

	for _, candidate := range candidates {
		uploadable, err := r.uploadable(ctx, p, key, report.GetKind(), candidate)
		if err != nil {
			return "", err
		}

		if uploadable {
			return candidate.name, nil
		}
	}

	return "", nil
}

// reportsOfKind returns the reports of the kind in the namespace by resource and container. The metadata of the
// kind is listed once per pass.
func (r *Reconciler) reportsOfKind(
	ctx context.Context,
	p *pass,
	kind string,
) (map[containerKey][]indexedReport, error) {
	if index, ok := p.reportIndex[kind]; ok {
		return index, nil
	}

	index, err := r.listReportIndex(ctx, p.target.Namespace, kind)
	if err != nil {
		return nil, err
	}

	p.reportIndex[kind] = index

	return index, nil
}

// listReportIndex lists the metadata of the reports of a kind page by page. A kind the cluster does not serve has
// none. When the listing starts again (see trivy.ListPages) the index starts empty.
func (r *Reconciler) listReportIndex(
	ctx context.Context,
	namespace, kind string,
) (map[containerKey][]indexedReport, error) {
	index := map[containerKey][]indexedReport{}

	err := trivy.ListPages(ctx, trivy.Listing[*metav1.PartialObjectMetadataList]{
		Reader:    r.reader,
		Namespace: namespace,
		What:      "the metadata of " + kind,
		PageSize:  reportMetadataPageSize,

		KindMayBeUnserved: true,
		NewList: func() *metav1.PartialObjectMetadataList {
			list := &metav1.PartialObjectMetadataList{}
			list.SetGroupVersionKind(trivy.ReportGVK(kind).GroupVersion().WithKind(kind + "List"))

			return list
		},
		Each: func(list *metav1.PartialObjectMetadataList) error {
			for i := range list.Items {
				indexReport(index, &list.Items[i])
			}

			return nil
		},
		Restart: func() { clear(index) },
	})

	switch {
	case errors.Is(err, trivy.ErrKindNotServed):
		return map[containerKey][]indexedReport{}, nil
	case err != nil:
		return nil, err
	}

	return index, nil
}

// indexReport adds the report to the index unless it is marked for deletion, expired or names no resource or
// container.
func indexReport(index map[containerKey][]indexedReport, report *metav1.PartialObjectMetadata) {
	if report.GetDeletionTimestamp() != nil || trivy.ExpiredReport(report) {
		return
	}

	kind, name := trivy.ResourceRef(report)
	container := trivy.ContainerOf(report)

	if kind == "" || name == "" || container == "" {
		return
	}

	key := containerKey{kind: strings.ToLower(kind), name: name, container: container}

	index[key] = append(index[key], indexedReport{
		name:    report.GetName(),
		version: versionOf(report),
	})
}

// uploadable reports whether the candidate is a report reimportOne uploads for the test: its version is not a held
// rejected version and the report is not broken. A candidate reimported in an earlier pass is known to be neither;
// the body of any other is read once to look for the break that metadata does not show.
func (r *Reconciler) uploadable(
	ctx context.Context,
	p *pass,
	key testKey,
	kind string,
	candidate indexedReport,
) (bool, error) {
	namespace := p.target.Namespace

	if r.isRejected(namespace, key, candidate.version) {
		return false, nil
	}

	if last := r.lastReimport(namespace, key); last != nil && last.reportVersion == candidate.version {
		return true, nil
	}

	full := &unstructured.Unstructured{}
	full.SetGroupVersionKind(trivy.ReportGVK(kind))

	err := r.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: candidate.name}, full)

	switch {
	case err == nil:
	case k8sErrors.IsNotFound(err):
		return false, nil
	default:
		return false, fmt.Errorf("failed to get %s %s: %w", kind, candidate.name, err)
	}

	return trivy.BrokenReport(full) == "", nil
}
