package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func reportMetadata(managed []metav1.ManagedFieldsEntry) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{APIVersion: "aquasecurity.github.io/v1alpha1", Kind: "VulnerabilityReport"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "replicaset-app-5d8f7c9b4-app",
			Namespace:       "team-a",
			UID:             "0c6f1e0a-7d4b-4c1e-9a53-2f1d8e7b6a10",
			ResourceVersion: "4711",
			Labels:          map[string]string{"trivy-operator.resource.kind": "ReplicaSet"},
			ManagedFields:   managed,
		},
	}
}

func namespace(managed []metav1.ManagedFieldsEntry) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "team-a",
			Labels:        map[string]string{"kubernetes.io/metadata.name": "team-a"},
			ManagedFields: managed,
		},
	}
}

func TestManagerOptionsCacheStripsManagedFields(t *testing.T) {
	managed := []metav1.ManagedFieldsEntry{{Manager: "trivy-operator", Operation: metav1.ManagedFieldsOperationUpdate}}

	tests := []struct {
		name string
		in   client.Object
		want client.Object
	}{
		{name: "report metadata", in: reportMetadata(managed), want: reportMetadata(nil)},
		{name: "namespace", in: namespace(managed), want: namespace(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transform := managerOptions("0", ":8081", false).Cache.DefaultTransform
			require.NotNil(t, transform)

			out, err := transform(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
		})
	}
}

func TestManagerOptions(t *testing.T) {
	opts := managerOptions(":8080", ":9440", true)

	assert.Same(t, scheme, opts.Scheme)
	assert.Equal(t, ":8080", opts.Metrics.BindAddress)
	assert.Equal(t, ":9440", opts.HealthProbeBindAddress)
	assert.True(t, opts.LeaderElection)
	assert.Equal(t, "krci-security-operator.edp.epam.com", opts.LeaderElectionID)
}
