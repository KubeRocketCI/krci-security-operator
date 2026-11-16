package trivy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
		{name: "namespace", want: "my-ns"},
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
			assert.Equal(t, tt.want, Component(tt.labels, tt.annotations, "my-ns", tt.prefixes))
		})
	}
}

func TestTagSafe(t *testing.T) {
	assert.Equal(t, "a-b-c-d", TagSafe("A b,C\td"))
	assert.Empty(t, TagSafe("  "))
}

func TestWorkload_GVK(t *testing.T) {
	tests := []struct {
		kind string
		want schema.GroupVersionKind
		ok   bool
	}{
		{"deployment", schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, true},
		{"statefulset", schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}, true},
		{"daemonset", schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}, true},
		{"cronjob", schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}, true},
		{"job", schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}, true},
		{"pod", schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, true},
		{"replicaset", schema.GroupVersionKind{}, false},
		{"replicationcontroller", schema.GroupVersionKind{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got, ok := Workload{Kind: tt.kind, Name: "x"}.GVK()

			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
