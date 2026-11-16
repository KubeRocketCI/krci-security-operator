// Package trivy maps Trivy Operator reports to DefectDojo imports.
package trivy

import (
	"maps"
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

	TagPrefixScope     = "krci-scope"
	TagPrefixTenant    = "krci-tenant"
	TagPrefixEnv       = "krci-env"
	TagPrefixNamespace = "krci-namespace"
	TagPrefixCluster   = "krci-cluster"

	TagScopeRuntime  = TagPrefixScope + ":runtime"
	TagScopeTenant   = TagPrefixScope + ":tenant"
	TagScopePlatform = TagPrefixScope + ":platform"

	// EngagementPrefixRuntime prefixes the runtime engagement name: "runtime:<cdPipeline>-<stage>".
	EngagementPrefixRuntime = "runtime"
	// EngagementPrefixNamespace prefixes the engagement of the tenant and platform scopes: "namespace:<ns>".
	EngagementPrefixNamespace = "namespace"
	// ProductPrefixEnvironment prefixes the product of workloads that belong to no codebase: "env:<cdPipeline>-<stage>".
	ProductPrefixEnvironment = "env"
	// ProductPrefixTenant prefixes the product of the tenant scope: "tenant:<tenant>".
	ProductPrefixTenant = "tenant"

	tagPrefixWorkload  = "krci-workload"
	tagPrefixContainer = "krci-container"
	tagPrefixCodebase  = "krci-codebase"
	tagPrefixComponent = "krci-component"

	digestVersionLen = len("sha256:") + 12
)

// ReportKinds lists the Trivy Operator report kinds that are imported.
var ReportKinds = []string{KindVulnerabilityReport, KindExposedSecretReport}

// ReportGVK returns the GroupVersionKind of a report kind.
func ReportGVK(kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: TrivyGroup, Version: TrivyVersion, Kind: kind}
}

// TenantTag is the tag that names the tenant of a test.
func TenantTag(tenant string) string { return TagPrefixTenant + ":" + tenant }

// NamespaceTag is the tag that ties a DefectDojo test to the namespace of its workload.
func NamespaceTag(namespace string) string { return TagPrefixNamespace + ":" + namespace }

// ClusterTag is the tag that ties a DefectDojo test to the operator instance of a cluster.
func ClusterTag(cluster string) string { return TagPrefixCluster + ":" + cluster }

// ComponentTag is the tag that names the component a workload belongs to.
func ComponentTag(component string) string { return tagPrefixComponent + ":" + component }

// ImportTitle is the title of the DefectDojo test of a workload container:
// "<ReportKind> <namespace>/<kind>/<name>/<container>".
// It is unique per namespace, so tests of equally named workloads of two namespaces never meet.
func ImportTitle(reportKind, namespace string, workload Workload, container string) string {
	return reportKind + " " + namespace + "/" + workload.String() + "/" + container
}

// EnvTag is the tag that ties a DefectDojo test to a Stage.
func EnvTag(cdPipeline, stage string) string { return TagPrefixEnv + ":" + cdPipeline + "." + stage }

// Scope is the kind of a namespace that decides where its reports go.
type Scope string

const (
	// ScopeStage is a namespace of a Stage.
	ScopeStage Scope = "stage"
	// ScopeTenant is a tenant namespace that belongs to no Stage.
	ScopeTenant Scope = "tenant"
	// ScopePlatform is any other namespace.
	ScopePlatform Scope = "platform"
)

// Tag is the "krci-scope" tag of the scope; the stage scope is tagged "runtime".
func (s Scope) Tag() string {
	switch s {
	case ScopeStage:
		return TagScopeRuntime
	case ScopeTenant:
		return TagScopeTenant
	default:
		return TagScopePlatform
	}
}

// IsOwned reports whether the test was written by the operator of the cluster:
// it carries the cluster tag and a "krci-scope" tag of the operator.
// The operator closes no other test.
func IsOwned(test defectdojo.Test, cluster string) bool {
	if !test.HasTag(ClusterTag(cluster)) {
		return false
	}

	return test.HasTag(TagScopeRuntime) || test.HasTag(TagScopeTenant) || test.HasTag(TagScopePlatform)
}

// Target is a classified namespace and the names its reports are imported under.
type Target struct {
	Scope     Scope
	Namespace string
	// Cluster is the operator's cluster name.
	Cluster string
	// Tenant is the value of the tenant label of the namespace; empty in the platform scope.
	Tenant string
	// CDPipeline and Stage name the Stage of the stage scope.
	CDPipeline string
	Stage      string
	// PlatformProduct is the product of the platform scope.
	PlatformProduct string
}

// Import is the DefectDojo destination and the descriptive fields of one report.
type Import struct {
	Product    string
	Engagement string
	TestTitle  string
	Version    string
	Tags       []string
	// Codebase is empty for images that belong to no codebase of the tenant.
	Codebase string
}

// ReportImport derives the DefectDojo destination of a report of a workload container in a namespace.
// In the stage scope the product is the codebase that owns the image, or an environment product for any other image.
// The codebases map is read in the stage scope only.
func ReportImport(
	target Target,
	report *unstructured.Unstructured,
	workload Workload,
	codebases map[string]string,
	component string,
) Import {
	image := ImageOf(report)
	container := report.GetLabels()[LabelContainerName]

	var (
		product, engagement, codebase string
		tags                          = []string{target.Scope.Tag()}
	)

	switch target.Scope {
	case ScopeStage:
		codebase = codebases[image.Name]
		engagement = EngagementPrefixRuntime + ":" + target.CDPipeline + "-" + target.Stage

		product = ProductPrefixEnvironment + ":" + target.CDPipeline + "-" + target.Stage
		if codebase != "" {
			product = codebase
		}

		tags = append(tags, TenantTag(target.Tenant), EnvTag(target.CDPipeline, target.Stage))
	case ScopeTenant:
		product = ProductPrefixTenant + ":" + target.Tenant
		engagement = EngagementPrefixNamespace + ":" + target.Namespace
		tags = append(tags, TenantTag(target.Tenant))
	default:
		product = target.PlatformProduct
		engagement = EngagementPrefixNamespace + ":" + target.Namespace
	}

	tags = append(tags,
		NamespaceTag(target.Namespace),
		tagPrefixWorkload+":"+workload.Tag(),
		tagPrefixContainer+":"+container,
	)
	if codebase != "" {
		tags = append(tags, tagPrefixCodebase+":"+codebase)
	}

	tags = append(tags, ComponentTag(component), ClusterTag(target.Cluster))

	version := image.Tag
	if version == "" {
		version = image.Digest[:min(len(image.Digest), digestVersionLen)]
	}

	return Import{
		Product:    product,
		Engagement: engagement,
		TestTitle:  ImportTitle(report.GetKind(), target.Namespace, workload, container),
		Version:    version,
		Tags:       tags,
		Codebase:   codebase,
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

	if kind := stableKinds[workload.Kind]; kind != "" {
		labels, _ := metadata["labels"].(map[string]any)
		labels = maps.Clone(labels)

		if labels == nil {
			labels = map[string]any{}
		}

		labels[LabelResourceKind] = kind
		labels[LabelResourceName] = workload.Name
		metadata["labels"] = labels
	}

	out["metadata"] = metadata

	return out
}

// stableKinds are the workload kinds that replace the resource kind of their reports.
var stableKinds = map[string]string{workloadDeployment: kindDeployment, workloadCronJob: kindCronJob}

// Service returns the finding service DefectDojo derives from the report sent by Payload.
func Service(report *unstructured.Unstructured, workload Workload) string {
	labels := report.GetLabels()
	namespace := labels[LabelResourceNamespace]

	if namespace == "" {
		namespace = report.GetNamespace()
	}

	kind, name := labels[LabelResourceKind], labels[LabelResourceName]
	if stable := stableKinds[workload.Kind]; stable != "" {
		kind, name = stable, workload.Name
	}

	return namespace + "/" + kind + "/" + name + "/" + labels[LabelContainerName]
}
