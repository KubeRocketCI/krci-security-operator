package trivy

import (
	"strings"
	"unicode"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	annotationArgoTrackingID = "argocd.argoproj.io/tracking-id"
	labelArgoInstance        = "argocd.argoproj.io/instance"
	labelPartOf              = "app.kubernetes.io/part-of"
	annotationHelmRelease    = "meta.helm.sh/release-name"
	labelInstance            = "app.kubernetes.io/instance"
)

// GVK returns the GroupVersionKind of the workload object whose labels and annotations name its component.
// ok is false for a workload kind that carries no component.
func (w Workload) GVK() (gvk schema.GroupVersionKind, ok bool) {
	switch w.Kind {
	case workloadDeployment:
		return schema.GroupVersionKind{Group: groupApps, Version: "v1", Kind: kindDeployment}, true
	case "statefulset":
		return schema.GroupVersionKind{Group: groupApps, Version: "v1", Kind: "StatefulSet"}, true
	case "daemonset":
		return schema.GroupVersionKind{Group: groupApps, Version: "v1", Kind: "DaemonSet"}, true
	case workloadCronJob:
		return schema.GroupVersionKind{Group: groupBatch, Version: "v1", Kind: kindCronJob}, true
	case workloadJob:
		return schema.GroupVersionKind{Group: groupBatch, Version: "v1", Kind: kindJob}, true
	case "pod":
		return schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, true
	default:
		return schema.GroupVersionKind{}, false
	}
}

// Component returns the component a workload belongs to, as a tag-safe value.
// The first source present wins:
// the app part of the Argo CD tracking-id annotation without the prefixes, the Argo CD instance label,
// the part-of label, the Helm release annotation, the instance label, and the namespace name.
func Component(labels, annotations map[string]string, namespace string, prefixes []string) string {
	candidates := []string{
		stripPrefixes(trackingApp(annotations[annotationArgoTrackingID]), prefixes),
		labels[labelArgoInstance],
		labels[labelPartOf],
		annotations[annotationHelmRelease],
		labels[labelInstance],
	}

	for _, c := range candidates {
		if c = TagSafe(c); c != "" {
			return c
		}
	}

	return TagSafe(namespace)
}

// TagSafe lower-cases the value and replaces spaces and commas, which DefectDojo tags cannot hold.
func TagSafe(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))

	return strings.Map(func(r rune) rune {
		if r == ',' || unicode.IsSpace(r) {
			return '-'
		}

		return r
	}, v)
}

// trackingApp returns the application name of an Argo CD tracking-id:
// "<app>:<group>/<kind>:<namespace>/<name>", where <app> may be prefixed "<namespace>_".
func trackingApp(id string) string {
	app, _, _ := strings.Cut(id, ":")

	return app[strings.LastIndex(app, "_")+1:]
}

func stripPrefixes(v string, prefixes []string) string {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(v, p) {
			return strings.TrimPrefix(v, p)
		}
	}

	return v
}
