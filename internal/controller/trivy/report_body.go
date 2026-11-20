package trivy

import (
	"context"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// versionFacts are what the body of a report version tells a pass before the upload. They do not change while the
// version holds.
type versionFacts struct {
	kind  string
	image trivy.Image
	// broken is the reason from trivy.BrokenBody; "" when the body can be uploaded.
	broken string
}

// readResult compares the report version a read returned with the requested one, by equality only.
type readResult int

const (
	sameVersion readResult = iota
	// otherVersion is a changed report, or one created again under the same name.
	otherVersion
	// gone is a report the API server does not have (404).
	gone
)

func (r readResult) String() string {
	switch r {
	case otherVersion:
		return "other version"
	case gone:
		return "gone"
	case sameVersion:
	}

	return "same version"
}

// reportBodies reads report bodies for one pass over a namespace and the facts of their versions. A body goes to the
// caller and is never kept here.
type reportBodies struct {
	reader    client.Reader
	namespace string
	// known returns the facts the reconciler kept from earlier passes.
	known func(reportVersion) (versionFacts, bool)
	// read holds the facts of the versions read in this pass.
	read map[reportVersion]versionFacts
}

func newReportBodies(
	reader client.Reader,
	namespace string,
	known func(reportVersion) (versionFacts, bool),
) *reportBodies {
	return &reportBodies{reader: reader, namespace: namespace, known: known, read: map[reportVersion]versionFacts{}}
}

// facts returns the facts of the version of the report: from this pass, then from earlier passes, with sameVersion
// and no body; else from one GET. A GET hands its body to the caller: on sameVersion and otherVersion the facts are
// those of the version read, and on gone there are none.
func (b *reportBodies) facts(
	ctx context.Context,
	m reportMeta,
) (f versionFacts, read readResult, body *unstructured.Unstructured, err error) {
	version := versionOf(m.obj)

	if inPass, ok := b.read[version]; ok {
		return inPass, sameVersion, nil, nil
	}

	if earlier, ok := b.known(version); ok {
		return earlier, sameVersion, nil, nil
	}

	body, read, err = b.get(ctx, m)
	if err != nil || read == gone {
		return versionFacts{}, read, nil, err
	}

	return b.read[versionOf(body)], read, body, nil
}

// bodyFor reads the body of the report for its upload with one GET. Only a sameVersion body is the version of the
// report.
func (b *reportBodies) bodyFor(ctx context.Context, m reportMeta) (*unstructured.Unstructured, readResult, error) {
	return b.get(ctx, m)
}

// get reads the report and records the facts of the version it returns.
func (b *reportBodies) get(ctx context.Context, m reportMeta) (*unstructured.Unstructured, readResult, error) {
	gvk := trivy.ReportGVK(m.kind)

	body := &unstructured.Unstructured{}
	body.SetGroupVersionKind(gvk)

	err := b.reader.Get(ctx, client.ObjectKey{Namespace: b.namespace, Name: m.obj.GetName()}, body)

	switch {
	case k8sErrors.IsNotFound(err):
		return nil, gone, nil
	case err != nil:
		return nil, sameVersion, fmt.Errorf("failed to get %s %s: %w", m.kind, m.obj.GetName(), err)
	}

	body.SetGroupVersionKind(gvk)

	b.read[versionOf(body)] = versionFacts{
		kind:   m.kind,
		image:  trivy.ReportImage(body),
		broken: trivy.BrokenBody(m.kind, body),
	}

	if versionOf(body) != versionOf(m.obj) {
		return body, otherVersion, nil
	}

	return body, sameVersion, nil
}
