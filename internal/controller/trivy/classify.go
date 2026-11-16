package trivy

import (
	"cmp"
	"context"
	"fmt"
	"path"
	"slices"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	// tenantLabel names the tenant of a namespace.
	tenantLabel = "app.edp.epam.com/tenant"
	// inClusterName is the clusterName of a Stage that runs in the cluster of the operator.
	inClusterName = "in-cluster"
)

var (
	stageGVK       = schema.GroupVersionKind{Group: "v2.edp.epam.com", Version: "v1", Kind: "Stage"}
	imageStreamGVK = schema.GroupVersionKind{Group: "v2.edp.epam.com", Version: "v1", Kind: "CodebaseImageStream"}
)

// stageRef holds the fields of a Stage the classification reads.
type stageRef struct {
	namespace       string
	name            string
	cdPipeline      string
	stage           string
	clusterName     string
	targetNamespace string
}

func parseStage(u *unstructured.Unstructured) stageRef {
	field := func(name string) string {
		v, _, _ := unstructured.NestedString(u.Object, "spec", name)

		return v
	}

	return stageRef{
		namespace:       u.GetNamespace(),
		name:            u.GetName(),
		cdPipeline:      field("cdPipeline"),
		stage:           field("name"),
		clusterName:     field("clusterName"),
		targetNamespace: field("namespace"),
	}
}

func (s stageRef) String() string { return s.namespace + "/" + s.name }

// invalidName returns the Stage field that is not an RFC 1123 DNS label, or an empty string.
// The names end up in DefectDojo tags and titles, where a comma or a dot would forge or blur a tag.
func (s stageRef) invalidName() string {
	fields := []struct{ name, value string }{
		{"spec.cdPipeline", s.cdPipeline},
		{"spec.name", s.stage},
		{"spec.namespace", s.targetNamespace},
	}

	for _, f := range fields {
		if len(validation.IsDNS1123Label(f.value)) > 0 {
			return f.name
		}
	}

	return ""
}

// classify decides the scope of a namespace and whether the operator imports its reports.
// A namespace is out of scope when it is excluded or when its scope is switched off.
func (r *Reconciler) classify(ctx context.Context, ns *corev1.Namespace) (trivy.Target, bool, error) {
	target := trivy.Target{
		Scope:           trivy.ScopePlatform,
		Namespace:       ns.Name,
		Cluster:         r.config.ClusterName,
		Tenant:          ns.Labels[tenantLabel],
		PlatformProduct: r.config.PlatformProduct,
	}

	if r.excluded(ns.Name) {
		return target, false, nil
	}

	if target.Tenant != "" {
		target.Scope = trivy.ScopeTenant

		stage, found, err := r.matchStage(ctx, ns.Name, target.Tenant)
		if err != nil {
			return target, false, err
		}

		if found {
			target.Scope = trivy.ScopeStage
			target.CDPipeline = stage.cdPipeline
			target.Stage = stage.stage
		}
	}

	return target, r.scopeEnabled(target.Scope), nil
}

func (r *Reconciler) scopeEnabled(scope trivy.Scope) bool {
	switch scope {
	case trivy.ScopeStage:
		return r.config.Scopes.Stage
	case trivy.ScopeTenant:
		return r.config.Scopes.Tenant
	default:
		return r.config.Scopes.Platform
	}
}

func (r *Reconciler) excluded(namespace string) bool {
	for _, pattern := range r.config.ExcludeNamespaces {
		if ok, err := path.Match(pattern, namespace); err == nil && ok {
			return true
		}
	}

	return false
}

// matchStage returns the Stage that makes the namespace a Stage namespace.
// The Stage is in-cluster, names the namespace, carries DNS label names and lives in the namespace the tenant
// label points at. When several Stages match, the first by namespace and name wins and the others are logged.
func (r *Reconciler) matchStage(ctx context.Context, namespace, tenant string) (stageRef, bool, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(stageGVK.GroupVersion().WithKind(stageGVK.Kind + "List"))

	if err := r.cache.List(ctx, list); err != nil {
		if meta.IsNoMatchError(err) {
			return stageRef{}, false, nil
		}

		return stageRef{}, false, fmt.Errorf("failed to list Stages: %w", err)
	}

	var matches []stageRef

	for i := range list.Items {
		s := parseStage(&list.Items[i])

		if s.targetNamespace != namespace || s.clusterName != inClusterName || s.namespace != tenant {
			continue
		}

		if field := s.invalidName(); field != "" {
			ctrl.LoggerFrom(ctx).Info("Stage field is not an RFC 1123 DNS label, the Stage is ignored",
				"stage", s.String(), "field", field)

			continue
		}

		matches = append(matches, s)
	}

	if len(matches) == 0 {
		return stageRef{}, false, nil
	}

	slices.SortFunc(matches, func(a, b stageRef) int {
		return cmp.Or(cmp.Compare(a.namespace, b.namespace), cmp.Compare(a.name, b.name))
	})

	if len(matches) > 1 {
		ignored := make([]string, 0, len(matches)-1)
		for _, s := range matches[1:] {
			ignored = append(ignored, s.String())
		}

		ctrl.LoggerFrom(ctx).Info("Several Stages claim the namespace, the first one is used",
			"stage", matches[0].String(), "ignored", ignored)
	}

	return matches[0], true, nil
}

// liveNamespace returns the namespace, or nil when it is gone or terminating.
func (r *Reconciler) liveNamespace(ctx context.Context, name string) (*corev1.Namespace, error) {
	ns := &corev1.Namespace{}

	if err := r.cache.Get(ctx, client.ObjectKey{Name: name}, ns); err != nil {
		if k8sErrors.IsNotFound(err) {
			return nil, nil //nolint:nilnil // a missing namespace is a result, not an error
		}

		return nil, fmt.Errorf("failed to get namespace %s: %w", name, err)
	}

	if ns.DeletionTimestamp != nil {
		return nil, nil //nolint:nilnil // a terminating namespace is out of scope like a missing one
	}

	return ns, nil
}

// namespaceInScope reports whether the operator imports the reports of the namespace.
// A namespace that is gone or terminating is out of scope.
func (r *Reconciler) namespaceInScope(ctx context.Context, name string) (bool, error) {
	ns, err := r.liveNamespace(ctx, name)
	if err != nil || ns == nil {
		return false, err
	}

	_, inScope, err := r.classify(ctx, ns)

	return inScope, err
}
