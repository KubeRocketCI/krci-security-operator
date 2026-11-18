package trivy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// metadataPageSize is the number of report metadata objects read per list call.
const metadataPageSize = 500

// ownKey identifies the reports of one container of a resource: the resource kind in lower case, its name and the
// container.
type ownKey struct {
	kind      string
	name      string
	container string
}

// ownCandidate is a report that is neither marked for deletion nor expired, as far as its metadata tells.
type ownCandidate struct {
	name    string
	version reportVersion
}

// ownReport returns the name of the report on the stable workload itself that names the same test as a report of
// one of its ReplicaSets or Jobs and that can be uploaded, or "" when there is none or the report is on the workload
// itself. The report on a ReplicaSet or Job is not uploaded then, whichever of the two the listing delivers first.
// A report that is marked for deletion, expired, broken or of a version DefectDojo rejected does not count.
func (r *Reconciler) ownReport(
	ctx context.Context,
	p *pass,
	key importKey,
	report *unstructured.Unstructured,
	workload trivy.Workload,
) (string, error) {
	if namesWorkload(report, workload) {
		return "", nil
	}

	index, err := r.ownCandidates(ctx, p, report.GetKind())
	if err != nil {
		return "", err
	}

	candidates := index[ownKey{
		kind:      workload.Kind,
		name:      workload.Name,
		container: report.GetLabels()[trivy.LabelContainerName],
	}]

	slices.SortFunc(candidates, func(a, b ownCandidate) int { return strings.Compare(a.name, b.name) })

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

// ownCandidates returns the reports of the kind in the namespace by resource and container. The metadata of the
// kind is listed once per pass.
func (r *Reconciler) ownCandidates(ctx context.Context, p *pass, kind string) (map[ownKey][]ownCandidate, error) {
	if index, ok := p.ownReports[kind]; ok {
		return index, nil
	}

	index, err := r.listCandidates(ctx, p.target.Namespace, kind)
	if err != nil {
		return nil, err
	}

	p.ownReports[kind] = index

	return index, nil
}

// listCandidates lists the metadata of the reports of a kind page by page. A kind the cluster does not serve has
// none. An expired continue token starts the listing again, up to maxListRestarts times.
func (r *Reconciler) listCandidates(ctx context.Context, namespace, kind string) (map[ownKey][]ownCandidate, error) {
	listKind := trivy.ReportGVK(kind).GroupVersion().WithKind(kind + "List")
	base := []client.ListOption{client.InNamespace(namespace), client.Limit(metadataPageSize)}
	opts := base
	restarts := 0
	index := map[ownKey][]ownCandidate{}

	for {
		list := &metav1.PartialObjectMetadataList{}
		list.SetGroupVersionKind(listKind)

		err := r.reader.List(ctx, list, opts...)

		switch {
		case err == nil:
		case meta.IsNoMatchError(err) || k8sErrors.IsNotFound(err):
			return map[ownKey][]ownCandidate{}, nil
		case continueExpired(err) && restarts < maxListRestarts:
			restarts++
			opts = base
			index = map[ownKey][]ownCandidate{}

			continue
		case continueExpired(err):
			return nil, fmt.Errorf("failed to list the metadata of %s after %d restarts: %w", kind, restarts, err)
		default:
			return nil, fmt.Errorf("failed to list the metadata of %s: %w", kind, err)
		}

		for i := range list.Items {
			addCandidate(index, &list.Items[i])
		}

		if list.GetContinue() == "" {
			return index, nil
		}

		opts = append(slices.Clone(base), client.Continue(list.GetContinue()))
	}
}

// addCandidate adds the report to the index unless it is marked for deletion, expired or names no resource or
// container.
func addCandidate(index map[ownKey][]ownCandidate, report *metav1.PartialObjectMetadata) {
	if report.GetDeletionTimestamp() != nil || trivy.ExpiredReport(report) {
		return
	}

	kind, name := trivy.ResourceRef(report)
	container := report.GetLabels()[trivy.LabelContainerName]

	if kind == "" || name == "" || container == "" {
		return
	}

	key := ownKey{kind: strings.ToLower(kind), name: name, container: container}

	index[key] = append(index[key], ownCandidate{
		name:    report.GetName(),
		version: reportVersion{uid: report.GetUID(), resourceVersion: report.GetResourceVersion()},
	})
}

// uploadable reports whether the candidate is a report importOne uploads for the test: its version is not
// rejected and the report is not broken. A candidate imported in an earlier pass is known to be neither; the body
// of any other is read once to look for the break that metadata does not show.
func (r *Reconciler) uploadable(
	ctx context.Context,
	p *pass,
	key importKey,
	kind string,
	candidate ownCandidate,
) (bool, error) {
	namespace := p.target.Namespace

	if r.isRejected(namespace, key, candidate.version) {
		return false, nil
	}

	if last, ok := r.lastImport(namespace, key); ok &&
		last.uid == candidate.version.uid && last.resourceVersion == candidate.version.resourceVersion {
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
