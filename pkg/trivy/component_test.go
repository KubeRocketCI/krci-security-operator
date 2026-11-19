package trivy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComponent(t *testing.T) {
	prefixes := []string{"in-cluster-"}

	tests := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		prefixes    []string
		want        string
	}{
		{
			name:        "tracking-id application",
			annotations: map[string]string{annotationArgoTrackingID: "my-app:apps/Deployment:ns/name"},
			want:        "my-app",
		},
		{
			name:        "tracking-id application in another namespace",
			annotations: map[string]string{annotationArgoTrackingID: "argocd_my-app:apps/Deployment:ns/name"},
			want:        "my-app",
		},
		{
			name:        "tracking-id without a resource part",
			annotations: map[string]string{annotationArgoTrackingID: "my-app"},
			want:        "my-app",
		},
		{
			name:        "prefix is stripped",
			annotations: map[string]string{annotationArgoTrackingID: "in-cluster-vault:apps/Deployment:ns/name"},
			prefixes:    prefixes,
			want:        "vault",
		},
		{
			name:        "prefix is kept when none is configured",
			annotations: map[string]string{annotationArgoTrackingID: "in-cluster-vault:apps/Deployment:ns/name"},
			want:        "in-cluster-vault",
		},
		{
			name:        "only the first matching prefix is stripped",
			annotations: map[string]string{annotationArgoTrackingID: "a-b-app:apps/Deployment:ns/name"},
			prefixes:    []string{"a-", "b-"},
			want:        "b-app",
		},
		{
			name:     "prefix is not stripped from the other sources",
			labels:   map[string]string{labelArgoInstance: "in-cluster-vault"},
			prefixes: prefixes,
			want:     "in-cluster-vault",
		},
		{
			name:   "Argo CD instance label",
			labels: map[string]string{labelArgoInstance: "legacy", labelPartOf: "suite", labelInstance: "inst"},
			want:   "legacy",
		},
		{
			name:        "part-of label",
			labels:      map[string]string{labelPartOf: "suite", labelInstance: "inst"},
			annotations: map[string]string{annotationHelmRelease: "release"},
			want:        "suite",
		},
		{
			name:        "Helm release annotation",
			labels:      map[string]string{labelInstance: "inst"},
			annotations: map[string]string{annotationHelmRelease: "release"},
			want:        "release",
		},
		{name: "instance label", labels: map[string]string{labelInstance: "inst"}, want: "inst"},
		{name: "no source gives no component"},
		{
			name:        "empty tracking-id application falls through",
			labels:      map[string]string{labelPartOf: "suite"},
			annotations: map[string]string{annotationArgoTrackingID: ":apps/Deployment:ns/name"},
			want:        "suite",
		},
		{
			name:        "application that is only a prefix falls through",
			labels:      map[string]string{labelPartOf: "suite"},
			annotations: map[string]string{annotationArgoTrackingID: "in-cluster-:apps/Deployment:ns/name"},
			prefixes:    prefixes,
			want:        "suite",
		},
		{name: "value is made tag-safe", labels: map[string]string{labelPartOf: " Big Suite,One "}, want: "big-suite-one"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Component(tt.labels, tt.annotations, tt.prefixes))
		})
	}
}

func TestTagSafe(t *testing.T) {
	assert.Equal(t, "a-b-c-d", TagSafe("A b,C\td"))
	assert.Equal(t, "a-b-c", TagSafe(`a'b"c`), "quotes are rejected by DefectDojo tags")
	assert.Empty(t, TagSafe("  "))
}
