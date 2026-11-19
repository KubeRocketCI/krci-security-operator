package trivy

import (
	"strings"
	"unicode"
)

const (
	annotationArgoTrackingID = "argocd.argoproj.io/tracking-id"
	labelArgoInstance        = "argocd.argoproj.io/instance"
	labelPartOf              = "app.kubernetes.io/part-of"
	annotationHelmRelease    = "meta.helm.sh/release-name"
	labelInstance            = "app.kubernetes.io/instance"
)

// Component returns the component a workload belongs to, as a tag-safe value, or "" when no source names one.
// The first source present wins:
// the app part of the Argo CD tracking-id annotation without the prefixes, the Argo CD instance label,
// the part-of label, the Helm release annotation, the instance label.
func Component(labels, annotations map[string]string, prefixes []string) string {
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

	return ""
}

// TagSafe lower-cases the value and replaces spaces, commas and quotes (' and "), which DefectDojo tags cannot
// hold, with "-".
func TagSafe(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))

	return strings.Map(func(r rune) rune {
		if r == ',' || r == '\'' || r == '"' || unicode.IsSpace(r) {
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
