package trivy

import (
	"context"
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// target is the namespace and the cluster its reports are imported for.
func (r *Reconciler) target(ns *corev1.Namespace) trivy.Target {
	return trivy.Target{
		Namespace: ns.Name,
		Cluster:   r.config.ClusterName,
		LabelTags: r.wantedLabelTags(ns, nil),
	}
}

// wantedLabelTags returns the namespace label tags that the product of a namespace has. ns is the namespace the
// operator imports, or nil for one it does not: the labels of such a namespace are not followed, so its product keeps
// the tags it has (have) for the listed keys.
func (r *Reconciler) wantedLabelTags(ns *corev1.Namespace, have []string) []string {
	if ns == nil {
		return trivy.NamespaceLabelTagsOfKeys(have, r.config.NamespaceLabelTags)
	}

	return trivy.NamespaceLabelTags(r.config.NamespaceLabelTags, ns.Labels)
}

// excluded reports whether the name of the namespace matches an exclude pattern.
func (r *Reconciler) excluded(namespace string) bool {
	for _, pattern := range r.config.ExcludeNamespaces {
		if ok, err := path.Match(pattern, namespace); err == nil && ok {
			return true
		}
	}

	return false
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
		return nil, nil //nolint:nilnil // a terminating namespace is gone like a missing one
	}

	return ns, nil
}

// importableNamespace returns the namespace when the operator imports its reports: it exists, is not terminating
// and is not excluded. Otherwise it returns nil.
func (r *Reconciler) importableNamespace(ctx context.Context, name string) (*corev1.Namespace, error) {
	ns, err := r.liveNamespace(ctx, name)
	if err != nil || ns == nil || r.excluded(ns.Name) {
		return nil, err
	}

	return ns, nil
}
