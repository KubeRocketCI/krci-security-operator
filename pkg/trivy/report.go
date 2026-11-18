// Package trivy maps Trivy Operator reports to DefectDojo imports.
package trivy

import (
	"maps"
	"strings"
	"time"

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

	TagPrefixNamespace = "krci-namespace"
	TagPrefixCluster   = "krci-cluster"

	// EngagementTrivyOperator is the engagement of a namespace product that holds the tests of this operator.
	EngagementTrivyOperator = "trivy-operator"

	tagPrefixWorkload  = "krci-workload"
	tagPrefixContainer = "krci-container"
	tagPrefixComponent = "krci-component"

	digestVersionLen = len("sha256:") + 12
)

// ReportKinds lists the Trivy Operator report kinds that are imported.
var ReportKinds = []string{KindVulnerabilityReport, KindExposedSecretReport}

// ReportGVK returns the GroupVersionKind of a report kind.
func ReportGVK(kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: TrivyGroup, Version: TrivyVersion, Kind: kind}
}

// NamespaceTag is the tag that ties a DefectDojo test to the namespace of its workload.
func NamespaceTag(namespace string) string { return TagPrefixNamespace + ":" + namespace }

// ClusterTag is the tag that ties a DefectDojo test to the operator instance of a cluster.
func ClusterTag(cluster string) string { return TagPrefixCluster + ":" + cluster }

// ComponentTag is the tag that names the component a workload belongs to.
func ComponentTag(component string) string { return tagPrefixComponent + ":" + component }

// ImportTitle is the title of the DefectDojo test of a workload container:
// "<ReportKind> <kind>/<name>/<container>". It has no namespace: the namespace product names it.
func ImportTitle(reportKind string, workload Workload, container string) string {
	return reportKind + " " + workload.String() + "/" + container
}

// ReportTitle is the title of the DefectDojo test of a report of a workload.
func ReportTitle(report *unstructured.Unstructured, workload Workload) string {
	return ImportTitle(report.GetKind(), workload, report.GetLabels()[LabelContainerName])
}

// ResourceRef returns the kind and the name of the resource a report was produced for.
// The name is the label, else the annotation of the same key: Trivy Operator writes a name that is not a valid
// label value only to the annotation.
func ResourceRef(report *unstructured.Unstructured) (kind, name string) {
	name = report.GetLabels()[LabelResourceName]
	if name == "" {
		name = report.GetAnnotations()[LabelResourceName]
	}

	return report.GetLabels()[LabelResourceKind], name
}

// NamesResource reports whether the report carries both the kind and the name of its resource.
func NamesResource(report *unstructured.Unstructured) bool {
	kind, name := ResourceRef(report)

	return kind != "" && name != ""
}

// TitleKind returns the report kind of a title written by ImportTitle.
func TitleKind(title string) string {
	kind, _, _ := strings.Cut(title, " ")

	return kind
}

// ProductName is the name of a namespace product: "<cluster name>/<namespace>".
func ProductName(cluster, namespace string) string { return cluster + "/" + namespace }

// IsOwned reports whether the test was written by the operator of the cluster: it carries the cluster tag.
// The operator closes no other test.
func IsOwned(test defectdojo.Test, cluster string) bool {
	return test.HasTag(ClusterTag(cluster))
}

// Target is a namespace and the cluster it lives in.
type Target struct {
	Namespace string
	// Cluster is the operator's cluster name.
	Cluster string
}

// Import is the DefectDojo destination and the descriptive fields of one report.
type Import struct {
	Product    string
	Engagement string
	TestTitle  string
	Version    string
	Tags       []string
}

// ReportImport derives the DefectDojo destination of a report of a workload container in a namespace:
// the namespace product, the engagement of the integration and the test of the container.
func ReportImport(target Target, report *unstructured.Unstructured, workload Workload, component string) Import {
	image := ImageOf(report)
	container := report.GetLabels()[LabelContainerName]

	version := image.Tag
	if version == "" {
		version = image.Digest[:min(len(image.Digest), digestVersionLen)]
	}

	return Import{
		Product:    ProductName(target.Cluster, target.Namespace),
		Engagement: EngagementTrivyOperator,
		TestTitle:  ReportTitle(report, workload),
		Version:    version,
		Tags: []string{
			NamespaceTag(target.Namespace),
			tagPrefixWorkload + ":" + workload.Tag(),
			tagPrefixContainer + ":" + container,
			ComponentTag(component),
			ClusterTag(target.Cluster),
		},
	}
}

// Request completes the import into a DefectDojo re-import request.
func (i Import) Request(productType string, scanDate time.Time, report []byte) defectdojo.ReimportRequest {
	return defectdojo.ReimportRequest{
		ProductType: productType,
		Product:     i.Product,
		Engagement:  i.Engagement,
		TestTitle:   i.TestTitle,
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
func BrokenReport(report *unstructured.Unstructured) string {
	if !NamesResource(report) {
		return "no resource kind or name"
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

// Payload returns the report ready to be marshalled, without the fields DefectDojo does not need.
// Only the top level and the metadata are copied; the report body is shared with the original and must not be
// modified, so a report is not held in memory twice.
// The Trivy Operator parser builds the finding service from the resource labels and DefectDojo closes
// findings only within one service, so the labels name the stable workload: a rollout then keeps one service.
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

// Service returns the finding service DefectDojo derives from the report sent by Payload.
func Service(report *unstructured.Unstructured, workload Workload) string {
	labels := report.GetLabels()
	namespace := labels[LabelResourceNamespace]

	if namespace == "" {
		namespace = report.GetNamespace()
	}

	kind, name := serviceResource(report, workload)

	return namespace + "/" + kind + "/" + name + "/" + labels[LabelContainerName]
}
