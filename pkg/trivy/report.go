// Package trivy maps Trivy Operator reports to DefectDojo reimports.
package trivy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"

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
	// names an image. Findings have none. The namespace label tags, see NamespaceLabelTags, are on products and tests
	// as well.
	TagKeyCluster   = "k8s-cluster"
	TagKeyNamespace = "k8s-namespace"
	// TagKeyWorkload is the stable workload of a test: "k8s-workload:<kind>.<name>", the kind in lower case, so the
	// kind ends at the first ".". The value is shortened over MaxTagLen; the operator never reads it back.
	TagKeyWorkload = "k8s-workload"
	// TagKeyContainer is the container of a test: "k8s-container:<container>".
	TagKeyContainer = "k8s-container"
	TagKeyImage     = "oci-image"
	TagKeyApp       = "app"
	// TagPrefixNamespaceLabel starts the key of a namespace label tag. The operator owns the prefix on a namespace
	// product: it adds, corrects and removes these tags and keeps every other tag.
	TagPrefixNamespaceLabel = "k8s-ns-label."
	// MaxNamespaceLabelKeyLen is the longest label key whose namespace label tag fits MaxTagLen with any label value.
	MaxNamespaceLabelKeyLen = MaxTagLen - len(TagPrefixNamespaceLabel) - len(":") - validation.LabelValueMaxLength

	// requestFormat is part of the upload marker. Bump it with every change to what a reimport sends that the marker
	// does not hold otherwise: Payload, the scan_date rule, a constant form field of defectdojo.Client.Reimport.
	// The next pass uploads every report once.
	requestFormat = 1

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

// ReportTitle is the title of the DefectDojo test of a report of the kind of a workload.
func ReportTitle(kind string, report metav1.Object, workload Workload) string {
	return TestTitle(kind, workload, ContainerOf(report))
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
func NamesResource(report metav1.Object) bool {
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

// NamespaceLabelTagKey is the key of the tag that the namespace label gives: "k8s-ns-label.<label key>", in lower
// case, the case DefectDojo stores the tags of a test in.
func NamespaceLabelTagKey(labelKey string) string {
	return TagPrefixNamespaceLabel + TagSafe(labelKey)
}

// NamespaceLabelTags returns the tag "k8s-ns-label.<label key>:<value>" of each of the keys that the labels hold, in
// the order of keys. The value is made tag-safe and shortened as in every tag. A key without a label, and a label
// with an empty value, give no tag.
func NamespaceLabelTags(keys []string, labels map[string]string) []string {
	var tags []string

	for _, key := range keys {
		if t := tag(NamespaceLabelTagKey(key), labels[key]); t != "" {
			tags = append(tags, t)
		}
	}

	return tags
}

// NamespaceLabelTagsOfKeys returns the namespace label tags among tags whose tag key is that of one of the label keys,
// in their order.
func NamespaceLabelTagsOfKeys(tags, keys []string) []string {
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[NamespaceLabelTagKey(key)] = struct{}{}
	}

	return slices.DeleteFunc(slices.Clone(tags), func(t string) bool {
		tagKey, _, _ := strings.Cut(t, ":")
		_, ok := wanted[tagKey]

		return !ok
	})
}

func isNamespaceLabelTag(t string) bool { return strings.HasPrefix(t, TagPrefixNamespaceLabel) }

// WithProductTags returns the tags a product keeps: its other tags, then the two product tags with the correct
// values, exactly once each, then labelTags, the namespace label tags it should have. The operator owns the
// namespace label tag prefix, so a tag of the product with it that is not in labelTags is dropped.
// changed is false when the product has them already.
func WithProductTags(have []string, cluster, namespace string, labelTags []string) (tags []string, changed bool) {
	for _, tag := range have {
		if !strings.HasPrefix(tag, TagKeyCluster+":") && !strings.HasPrefix(tag, TagKeyNamespace+":") &&
			!isNamespaceLabelTag(tag) {
			tags = append(tags, tag)
		}
	}

	tags = append(tags, ProductTags(cluster, namespace)...)
	tags = append(tags, labelTags...)

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
	// LabelTags are the namespace label tags of the namespace, see NamespaceLabelTags.
	LabelTags []string
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
	// Tags are the tags of the test: "k8s-cluster", "k8s-namespace", the namespace label tags, "k8s-workload",
	// "k8s-container", "oci-image" and, when component is not empty, "app". A tag with an empty value is left out; a
	// tag over MaxTagLen has its value shortened.
	Tags []string
}

// NewReimport derives the DefectDojo destination of a report of the kind of a workload container in a namespace:
// the namespace product, the engagement of the integration and the test of the container. It reads the labels,
// annotations and namespace of the report only.
// component is the value of the app tag; empty gives no app tag. image is the image of the report as the container
// reference names it, see Image.For.
func NewReimport(
	target Target,
	kind string,
	report metav1.Object,
	workload Workload,
	component string,
	image Image,
) Reimport {
	return Reimport{
		Product:    ProductName(target.Cluster, target.Namespace),
		Engagement: EngagementTrivyOperator,
		TestTitle:  ReportTitle(kind, report, workload),
		Service:    Service(report, workload),
		Version:    Shorten(image.Version(), MaxVersionLen),
		Tags: slices.DeleteFunc(slices.Concat(
			ProductTags(target.Cluster, target.Namespace),
			target.LabelTags,
			[]string{
				tag(TagKeyWorkload, workload.Tag()),
				tag(TagKeyContainer, ContainerOf(report)),
				tag(TagKeyImage, image.Name),
				tag(TagKeyApp, component),
			},
		), func(t string) bool { return t == "" }),
	}
}

// UploadMarker returns the build_id that marks the upload of the report with this request:
// "<report UID>:<resourceVersion>:<12 hex characters of the SHA-256 of the request>", shortened to MaxBuildIDLen.
// The request is the request format, the test title, the service, the version and the tags; a change of any of them
// changes the marker, so a report whose request changed is uploaded again. The same report version and request
// always give the same marker. The marker is only compared, never parsed.
func (i Reimport) UploadMarker(report metav1.Object) string {
	return Shorten(string(report.GetUID())+":"+report.GetResourceVersion()+":"+i.fingerprint(requestFormat), MaxBuildIDLen)
}

// fingerprint returns the first hashLen hex characters of the SHA-256 of the request for the request format.
func (i Reimport) fingerprint(format int) string {
	tags := slices.Sorted(slices.Values(i.Tags))
	sum := sha256.New()

	for _, field := range append([]string{strconv.Itoa(format), i.TestTitle, i.Service, i.Version}, tags...) {
		var length [8]byte

		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		sum.Write(length[:])
		sum.Write([]byte(field))
	}

	return hex.EncodeToString(sum.Sum(nil))[:hashLen]
}

// Request completes the reimport into a DefectDojo reimport request; buildID is the UploadMarker of the report.
func (i Reimport) Request(
	productType string,
	scanDate time.Time,
	buildID string,
	report []byte,
) defectdojo.ReimportRequest {
	return defectdojo.ReimportRequest{
		ProductType: productType,
		Product:     i.Product,
		Engagement:  i.Engagement,
		TestTitle:   i.TestTitle,
		Service:     i.Service,
		Version:     i.Version,
		BuildID:     buildID,
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

// BrokenLabels returns why the metadata of the report rules out its upload, or "" when it does not.
// A report without the resource kind or the resource name (see ResourceRef) is broken: it names no test.
// A report without the container name label is broken: it names no test. DefectDojo reads a report without labels as
// a report with no findings and closes the findings of its test.
func BrokenLabels(report metav1.Object) string {
	if !NamesResource(report) {
		return "no resource kind or name"
	}

	if ContainerOf(report) == "" {
		return "no container name"
	}

	return ""
}

// BrokenBody returns why the body of a report of the kind rules out its upload, or "" when it does not.
// DefectDojo reads a report without the report block or without its result list as a report with no findings and
// closes the findings of its test. Trivy Operator always writes the list, also when it is empty; an empty list is not
// broken. The body does not change while the report version holds.
func BrokenBody(kind string, report *unstructured.Unstructured) string {
	block, ok := report.Object["report"].(map[string]any)
	if !ok {
		return "no report block"
	}

	field, ok := resultFields[kind]
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
// Only the top level, the metadata and, when entries are dropped, the report block and its result list are
// copied; the other values are shared with the original and must not be modified, so a report is not held in
// memory twice.
// A result entry whose hash parts (entryHashParts) repeat an earlier entry is dropped; the first is kept.
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

	collapseEntries(out, report.GetKind())

	return out
}

// stableKinds are the workload kinds that replace the resource kind of their reports.
var stableKinds = map[string]string{workloadDeployment: kindDeployment, workloadCronJob: kindCronJob}

// serviceResource returns the resource kind and name the parser reads: the stable workload, else the report's own.
// The name is always written as a label, so a name found only in the annotation reaches the parser.
func serviceResource(report metav1.Object, workload Workload) (kind, name string) {
	if stable := stableKinds[workload.Kind]; stable != "" {
		return stable, workload.Name
	}

	return ResourceRef(report)
}

// Service returns the finding service DefectDojo derives from the report sent by Payload,
// "<namespace>/<Kind>/<name>/<container>", shortened to MaxServiceLen.
func Service(report metav1.Object, workload Workload) string {
	kind, name := serviceResource(report, workload)

	return Shorten(serviceNamespace(report)+"/"+kind+"/"+name+"/"+ContainerOf(report), MaxServiceLen)
}

// serviceNamespace returns the resource namespace label, else the namespace of the report.
func serviceNamespace(report metav1.Object) string {
	if namespace := report.GetLabels()[LabelResourceNamespace]; namespace != "" {
		return namespace
	}

	return report.GetNamespace()
}
