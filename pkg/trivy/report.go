// Package trivy maps Trivy Operator reports to DefectDojo reimports.
package trivy

import (
	"maps"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

const (
	// TrivyGroup is the API group of Trivy Operator reports.
	TrivyGroup = "aquasecurity.github.io"
	// TrivyVersion is the API version of Trivy Operator reports.
	TrivyVersion = "v1alpha1"

	KindVulnerabilityReport = "VulnerabilityReport"
	KindExposedSecretReport = "ExposedSecretReport"

	LabelResourceKind = "trivy-operator.resource.kind"
	LabelResourceName = "trivy-operator.resource.name"

	LabelResourceNamespace = "trivy-operator.resource.namespace"
	LabelContainerName     = "trivy-operator.container.name"

	// AnnotationReportTTL is the time Trivy Operator keeps a report. It marks a report it deletes at once with 0s.
	AnnotationReportTTL = "trivy-operator.aquasecurity.github.io/report-ttl"

	// EngagementTrivyOperator is the engagement of a namespace product that holds the tests of this operator.
	EngagementTrivyOperator = "trivy-operator"

	// The keys of the tags, written as "<key>:<value>". A namespace product has TagKeyCluster and TagKeyNamespace.
	// A test has all of them; TagKeyApp only when the workload names a component, TagKeyImage only when the report
	// names an image. Findings have none.
	TagKeyCluster   = "k8s-cluster"
	TagKeyNamespace = "k8s-namespace"
	// TagKeyWorkload is the stable workload of a test: "k8s-workload:<kind>.<name>", the kind in lower case, so the
	// kind ends at the first ".". The value is shortened over MaxTagLen; the operator never reads it back.
	TagKeyWorkload = "k8s-workload"
	// TagKeyContainer is the container of a test: "k8s-container:<container>".
	TagKeyContainer = "k8s-container"
	TagKeyImage     = "oci-image"
	TagKeyApp       = "app"

	// digestHexLen is the number of digest characters in a version without a tag.
	digestHexLen = 12
	digestAlgo   = "sha256"
)

// ReportKinds lists the Trivy Operator report kinds that are imported.
var ReportKinds = []string{KindVulnerabilityReport, KindExposedSecretReport}

// ReportGVK returns the GroupVersionKind of a report kind.
func ReportGVK(kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: TrivyGroup, Version: TrivyVersion, Kind: kind}
}

// TestTitle is the title of the DefectDojo test of a workload container:
// "<ReportKind> <kind>/<name>/<container>", shortened to MaxTitleLen. It has no namespace: the namespace product
// names it.
func TestTitle(reportKind string, workload Workload, container string) string {
	return Shorten(reportKind+" "+workload.String()+"/"+container, MaxTitleLen)
}

// ReportTitle is the title of the DefectDojo test of a report of a workload.
func ReportTitle(report *unstructured.Unstructured, workload Workload) string {
	return TestTitle(report.GetKind(), workload, ContainerOf(report))
}

// ResourceRef returns the kind and the name of the resource a report was produced for.
// The name is the label, else the annotation of the same key: Trivy Operator writes a name that is not a valid
// label value only to the annotation.
func ResourceRef(report metav1.Object) (kind, name string) {
	name = report.GetLabels()[LabelResourceName]
	if name == "" {
		name = report.GetAnnotations()[LabelResourceName]
	}

	return report.GetLabels()[LabelResourceKind], name
}

// ContainerOf returns the name of the container a report was produced for; "" when the report names none.
func ContainerOf(report metav1.Object) string { return report.GetLabels()[LabelContainerName] }

// NamesResource reports whether the report carries both the kind and the name of its resource.
func NamesResource(report *unstructured.Unstructured) bool {
	kind, name := ResourceRef(report)

	return kind != "" && name != ""
}

// TitleKind returns the report kind of a title written by TestTitle.
func TitleKind(title string) string {
	kind, _, _ := strings.Cut(title, " ")

	return kind
}

// ProductPrefix is the start of the name of every namespace product of the cluster: "<cluster name>/".
func ProductPrefix(cluster string) string { return cluster + "/" }

// ProductName is the name of a namespace product: "<cluster name>/<namespace>".
func ProductName(cluster, namespace string) string { return ProductPrefix(cluster) + namespace }

// IsOwned reports whether the operator of the cluster may close the test: its product name starts with
// "<cluster name>/" and its scan type is Trivy Operator Scan. Tags are not used.
func IsOwned(test defectdojo.Test, cluster string) bool {
	return strings.HasPrefix(test.Product, ProductPrefix(cluster)) && test.ScanType == defectdojo.ScanTypeTrivyOperator
}

// NamespaceOfProduct returns the namespace of a namespace product of the cluster, "<cluster name>/<namespace>".
// Any other product name, one without the prefix or with a further "/" for example, is not one.
func NamespaceOfProduct(cluster, product string) (string, bool) {
	namespace, ok := strings.CutPrefix(product, ProductPrefix(cluster))
	if !ok || namespace == "" || strings.Contains(namespace, "/") {
		return "", false
	}

	return namespace, true
}

// ProductTags returns the two tags of a namespace product: "k8s-cluster:<cluster>" and "k8s-namespace:<namespace>".
func ProductTags(cluster, namespace string) []string {
	return []string{tag(TagKeyCluster, cluster), tag(TagKeyNamespace, namespace)}
}

// tag returns "<key>:<value>" with the value made tag-safe and shortened so the tag has at most MaxTagLen
// characters, or "" when the value is empty.
func tag(key, value string) string {
	if value = TagSafe(value); value == "" {
		return ""
	}

	return key + ":" + Shorten(value, MaxTagLen-len(key)-1)
}

// WithProductTags returns the tags a product keeps: its other tags, then the two product tags with the correct
// values, exactly once each. changed is false when the product has them already.
func WithProductTags(have []string, cluster, namespace string) (tags []string, changed bool) {
	want := ProductTags(cluster, namespace)

	for _, tag := range have {
		if !strings.HasPrefix(tag, TagKeyCluster+":") && !strings.HasPrefix(tag, TagKeyNamespace+":") {
			tags = append(tags, tag)
		}
	}

	tags = append(tags, want...)

	return tags, !sameSet(have, tags)
}

// sameSet reports whether both lists hold the same tags, in any order.
func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// Target is a namespace and the cluster it lives in.
type Target struct {
	Namespace string
	// Cluster is the operator's cluster name.
	Cluster string
}

// Reimport is the DefectDojo destination and the descriptive fields of the reimport of one report.
type Reimport struct {
	Product    string
	Engagement string
	TestTitle  string
	// Service is the finding service, see Service.
	Service string
	// Version is the image tag of the report, else "sha256:" and the first 12 characters of its digest. The tag of the
	// report is ignored when the container reference in the pod template is its digest without a tag.
	Version string
	// Tags are the tags of the test: "k8s-cluster", "k8s-namespace", "k8s-workload", "k8s-container", "oci-image"
	// and, when component is not empty, "app". A tag with an empty value is left out; a tag over MaxTagLen has
	// its value shortened.
	Tags []string
}

// NewReimport derives the DefectDojo destination of a report of a workload container in a namespace:
// the namespace product, the engagement of the integration and the test of the container.
// component is the value of the app tag; empty gives no app tag. imageRef is the image reference of the container
// in the pod template of the workload, see ImageOf.
func NewReimport(
	target Target,
	report *unstructured.Unstructured,
	workload Workload,
	component, imageRef string,
) Reimport {
	image := ImageOf(report, imageRef)

	return Reimport{
		Product:    ProductName(target.Cluster, target.Namespace),
		Engagement: EngagementTrivyOperator,
		TestTitle:  ReportTitle(report, workload),
		Service:    Service(report, workload),
		Version:    Shorten(image.Version(), MaxVersionLen),
		Tags: slices.DeleteFunc([]string{
			tag(TagKeyCluster, target.Cluster),
			tag(TagKeyNamespace, target.Namespace),
			tag(TagKeyWorkload, workload.Tag()),
			tag(TagKeyContainer, ContainerOf(report)),
			tag(TagKeyImage, image.Name),
			tag(TagKeyApp, component),
		}, func(t string) bool { return t == "" }),
	}
}

// Request completes the reimport into a DefectDojo reimport request.
func (i Reimport) Request(productType string, scanDate time.Time, report []byte) defectdojo.ReimportRequest {
	return defectdojo.ReimportRequest{
		ProductType: productType,
		Product:     i.Product,
		Engagement:  i.Engagement,
		TestTitle:   i.TestTitle,
		Service:     i.Service,
		Version:     i.Version,
		Tags:        i.Tags,
		ScanDate:    scanDate,
		Report:      report,
	}
}

// resultFields names the list of results each report kind holds under "report".
var resultFields = map[string]string{
	KindVulnerabilityReport: "vulnerabilities",
	KindExposedSecretReport: "secrets",
}

// BrokenReport returns why the report must not be uploaded, or "" when it can be.
// DefectDojo reads a report without labels, without the report block or without its result list as a report
// with no findings and closes the findings of its test. Trivy Operator always writes the list, also when it is
// empty; an empty list is not broken.
// A report without the resource kind or the resource name (see ResourceRef) is broken: it names no test.
// A report without the container name label is broken: it names no test.
func BrokenReport(report *unstructured.Unstructured) string {
	if !NamesResource(report) {
		return "no resource kind or name"
	}

	if ContainerOf(report) == "" {
		return "no container name"
	}

	block, ok := report.Object["report"].(map[string]any)
	if !ok {
		return "no report block"
	}

	field, ok := resultFields[report.GetKind()]
	if !ok {
		return ""
	}

	if _, ok = block[field].([]any); !ok {
		return "no report." + field + " list"
	}

	return ""
}

// ExpiredReport reports whether Trivy Operator marked the report for deletion: its TTL annotation is 0s.
// Such a report is not current and is not imported.
func ExpiredReport(report metav1.Object) bool {
	ttl, ok := report.GetAnnotations()[AnnotationReportTTL]
	if !ok {
		return false
	}

	d, err := time.ParseDuration(ttl)

	return err == nil && d == 0
}

// Payload returns the report ready to be marshalled, without the fields DefectDojo does not need.
// Only the top level and the metadata are copied; the report body is shared with the original and must not be
// modified, so a report is not held in memory twice.
// The Trivy Operator parser builds the finding service from the resource namespace, kind and name labels and
// the container name label, and DefectDojo closes findings only within one service. The labels name the stable
// workload and the namespace, so the parser service equals Service and a rollout keeps one service.
func Payload(report *unstructured.Unstructured, workload Workload) map[string]any {
	out := maps.Clone(report.Object)

	metadata, _ := out["metadata"].(map[string]any)
	metadata = maps.Clone(metadata)

	if metadata == nil {
		metadata = map[string]any{}
	}

	delete(metadata, "managedFields")

	labels, _ := metadata["labels"].(map[string]any)
	labels = maps.Clone(labels)

	if labels == nil {
		labels = map[string]any{}
	}

	kind, name := serviceResource(report, workload)
	labels[LabelResourceNamespace] = serviceNamespace(report)
	labels[LabelResourceKind] = kind
	labels[LabelResourceName] = name
	metadata["labels"] = labels

	out["metadata"] = metadata

	return out
}

// stableKinds are the workload kinds that replace the resource kind of their reports.
var stableKinds = map[string]string{workloadDeployment: kindDeployment, workloadCronJob: kindCronJob}

// serviceResource returns the resource kind and name the parser reads: the stable workload, else the report's own.
// The name is always written as a label, so a name found only in the annotation reaches the parser.
func serviceResource(report *unstructured.Unstructured, workload Workload) (kind, name string) {
	if stable := stableKinds[workload.Kind]; stable != "" {
		return stable, workload.Name
	}

	return ResourceRef(report)
}

// Service returns the finding service DefectDojo derives from the report sent by Payload,
// "<namespace>/<Kind>/<name>/<container>", shortened to MaxServiceLen.
func Service(report *unstructured.Unstructured, workload Workload) string {
	kind, name := serviceResource(report, workload)

	return Shorten(serviceNamespace(report)+"/"+kind+"/"+name+"/"+ContainerOf(report), MaxServiceLen)
}

// serviceNamespace returns the resource namespace label, else the namespace of the report.
func serviceNamespace(report *unstructured.Unstructured) string {
	if namespace := report.GetLabels()[LabelResourceNamespace]; namespace != "" {
		return namespace
	}

	return report.GetNamespace()
}
