package trivy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// reportMetadataPageSize is the number of report metadata objects read per list call of the API reader.
const reportMetadataPageSize = 500

// reportMeta is the metadata of one report of a pass: name, namespace, UID, resourceVersion, labels, annotations and
// deletion timestamp. kind is the report kind, which metav1.Object does not carry.
type reportMeta struct {
	kind string
	obj  *metav1.PartialObjectMetadata
}

// containerKey identifies the reports of one container of a resource: the resource kind in lower case, its name and the
// container.
type containerKey struct {
	kind      string
	name      string
	container string
}

// reportListing is what a pass knows about the reports of its namespace. records is the one store of report metadata;
// everything else names a report by its kind and name and looks the record up when it needs it.
type reportListing struct {
	// records holds, per kind and name, the metadata of the reports the pass decides on: the listed version, or the
	// version a read returned instead (adopt).
	records map[string]map[string]reportMeta
	// worklist holds, per kind, the names of the listed reports in name order.
	worklist map[string][]string
	// index holds, per kind, the names of the reports of each container key in name order. A slice is never changed
	// in place: adopt writes a new one.
	index map[string]map[containerKey][]string
	// completed holds the kinds whose listing completed in this pass, an empty one included.
	completed map[string]struct{}
}

func newReportListing() reportListing {
	return reportListing{
		records:   map[string]map[string]reportMeta{},
		worklist:  map[string][]string{},
		index:     map[string]map[containerKey][]string{},
		completed: map[string]struct{}{},
	}
}

func (l *reportListing) record(kind, name string) (reportMeta, bool) {
	m, ok := l.records[kind][name]

	return m, ok
}

// candidates returns the names of the reports of the kind under the key, in name order. The slice must not be changed.
func (l *reportListing) candidates(kind string, key containerKey) []string { return l.index[kind][key] }

func (l *reportListing) isCompleted(kind string) bool {
	_, ok := l.completed[kind]

	return ok
}

func (l *reportListing) clear(kind string) {
	delete(l.records, kind)
	delete(l.worklist, kind)
	delete(l.index, kind)
}

func (l *reportListing) add(kind string, obj *metav1.PartialObjectMetadata) {
	if l.records[kind] == nil {
		l.records[kind] = map[string]reportMeta{}
	}

	l.records[kind][obj.GetName()] = reportMeta{kind: kind, obj: obj}
}

// finish builds the worklist and the index of the kind from its records and marks its listing completed.
func (l *reportListing) finish(kind string) {
	names := slices.Sorted(maps.Keys(l.records[kind]))
	index := map[containerKey][]string{}

	for _, name := range names {
		if key, ok := indexKey(l.records[kind][name].obj); ok {
			index[key] = append(index[key], name)
		}
	}

	l.worklist[kind] = names
	l.index[kind] = index
	l.completed[kind] = struct{}{}
}

// versions returns the report versions of the records of the kinds whose listing completed.
func (l *reportListing) versions() map[reportVersion]struct{} {
	out := map[reportVersion]struct{}{}

	for kind := range l.completed {
		for _, m := range l.records[kind] {
			out[versionOf(m.obj)] = struct{}{}
		}
	}

	return out
}

// adopt applies a read of the report that returned another version or found it gone, and returns the record the pass
// keeps; ok is false when it keeps none. Another version replaces the record with the metadata of the body and moves
// the name to the index key of that metadata, or out of the index; gone removes the record and the name. Every changed
// key gets a new slice.
func (l *reportListing) adopt(kind, name string, read readResult, body *unstructured.Unstructured) (reportMeta, bool) {
	if old, ok := l.records[kind][name]; ok {
		if key, indexed := indexKey(old.obj); indexed {
			l.index[kind][key] = slices.DeleteFunc(slices.Clone(l.index[kind][key]), func(n string) bool { return n == name })
		}

		delete(l.records[kind], name)
	}

	if read != otherVersion || body == nil || l.records[kind] == nil {
		return reportMeta{}, false
	}

	m := reportMeta{kind: kind, obj: metadataOf(kind, body)}
	l.records[kind][name] = m

	if key, ok := indexKey(m.obj); ok {
		names := slices.Clone(l.index[kind][key])
		at, _ := slices.BinarySearch(names, name)
		l.index[kind][key] = slices.Insert(names, at, name)
	}

	return m, true
}

// indexKey returns the container key of a report that may be uploaded as far as its metadata tells: it is not marked
// for deletion or expired, and names its resource and container.
func indexKey(report metav1.Object) (containerKey, bool) {
	if report.GetDeletionTimestamp() != nil || trivy.ExpiredReport(report) {
		return containerKey{}, false
	}

	kind, name := trivy.ResourceRef(report)
	container := trivy.ContainerOf(report)

	if kind == "" || name == "" || container == "" {
		return containerKey{}, false
	}

	return containerKey{kind: strings.ToLower(kind), name: name, container: container}, true
}

func metadataOf(kind string, body *unstructured.Unstructured) *metav1.PartialObjectMetadata {
	m := &metav1.PartialObjectMetadata{}
	m.SetGroupVersionKind(trivy.ReportGVK(kind))
	m.SetName(body.GetName())
	m.SetNamespace(body.GetNamespace())
	m.SetUID(body.GetUID())
	m.SetResourceVersion(body.GetResourceVersion())
	m.SetLabels(body.GetLabels())
	m.SetAnnotations(body.GetAnnotations())
	m.SetDeletionTimestamp(body.GetDeletionTimestamp())

	return m
}

// listReports lists the metadata of the reports of the kind in the namespace of the pass into its records, worklist
// and index. A kind watched at start is listed from the cache, any other through the API reader in pages. listed is
// false, without an error, when the cluster does not serve the kind. A failed listing leaves the kind without records.
func (r *Reconciler) listReports(ctx context.Context, p *pass, kind string) (listed bool, err error) {
	p.reports.clear(kind)

	if slices.Contains(r.watched, kind) {
		err = r.listCachedReports(ctx, p, kind)
	} else {
		err = r.listPagedReports(ctx, p, kind)
	}

	if err != nil {
		p.reports.clear(kind)

		if errors.Is(err, trivy.ErrKindNotServed) {
			return false, nil
		}

		return false, err
	}

	p.reports.finish(kind)

	return true, nil
}

// listCachedReports lists the metadata of a watched kind from the cache, in one call. A cache list of a kind that is
// not watched would start an informer for it.
func (r *Reconciler) listCachedReports(ctx context.Context, p *pass, kind string) error {
	list := reportMetadataList(kind)

	err := r.cache.List(ctx, list, client.InNamespace(p.target.Namespace))

	switch {
	case err == nil:
	case meta.IsNoMatchError(err) || k8sErrors.IsNotFound(err):
		return fmt.Errorf("failed to list the metadata of %s: %w: %w", kind, trivy.ErrKindNotServed, err)
	default:
		return fmt.Errorf("failed to list the metadata of %s: %w", kind, err)
	}

	for i := range list.Items {
		p.reports.add(kind, &list.Items[i])
	}

	return nil
}

// listPagedReports lists the metadata of a kind through the API reader, page by page. A restarted listing starts with
// no records of the kind.
func (r *Reconciler) listPagedReports(ctx context.Context, p *pass, kind string) error {
	return trivy.ListPages(ctx, trivy.Listing[*metav1.PartialObjectMetadataList]{
		Reader:    r.reader,
		Namespace: p.target.Namespace,
		What:      "the metadata of " + kind,
		PageSize:  reportMetadataPageSize,

		KindMayBeUnserved: true,
		NewList:           func() *metav1.PartialObjectMetadataList { return reportMetadataList(kind) },
		Each: func(list *metav1.PartialObjectMetadataList) error {
			for i := range list.Items {
				p.reports.add(kind, &list.Items[i])
			}

			return nil
		},
		Restart: func() { p.reports.clear(kind) },
	})
}

func reportMetadataList(kind string) *metav1.PartialObjectMetadataList {
	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(trivy.ReportGVK(kind).GroupVersion().WithKind(kind + "List"))

	return list
}
