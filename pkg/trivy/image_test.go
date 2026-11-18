package trivy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNormalizeImage(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{name: "registry with port and tag", ref: "registry.example.com:5000/krci/app:1.0.0", want: "registry.example.com:5000/krci/app"},
		{name: "registry with port without tag", ref: "registry.example.com:5000/krci/app", want: "registry.example.com:5000/krci/app"},
		{name: "digest", ref: "registry.example.com/krci/app@sha256:abc", want: "registry.example.com/krci/app"},
		{name: "tag and digest", ref: "registry.example.com/krci/app:1.0.0@sha256:abc", want: "registry.example.com/krci/app"},
		{name: "upper case", ref: "Registry.Example.com/KRCI/App:1", want: "registry.example.com/krci/app"},
		{name: "docker.io with library", ref: "docker.io/library/nginx:1.27", want: "nginx"},
		{name: "index.docker.io with library", ref: "index.docker.io/library/postgres", want: "postgres"},
		{name: "registry-1.docker.io", ref: "registry-1.docker.io/valkey/valkey:9", want: "valkey/valkey"},
		{name: "docker.io user image", ref: "docker.io/epamedp/cd-pipeline-operator:2.35.0", want: "epamedp/cd-pipeline-operator"},
		{name: "implicit docker hub", ref: "nginx:1.27", want: "nginx"},
		{name: "non hub library path is kept", ref: "quay.io/library/app", want: "quay.io/library/app"},
		{name: "empty", ref: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeImage(tt.ref))
		})
	}
}

func TestImageOf(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    Image
	}{
		{
			name:    "private registry",
			fixture: "vulnerabilityreport_replicaset.json",
			want: Image{
				Name:   "gitlab.127.0.0.1.nip.io:5050/krci/test-go-app",
				Tag:    "main-20261110-194848",
				Digest: "sha256:9155b03ee4d94b88f7ef3632b86417509c8d75bce88edc6c5c2b01eaf266a9c9",
			},
		},
		{
			name:    "docker hub official image",
			fixture: "vulnerabilityreport_dockerhub.json",
			want:    Image{Name: "postgres", Tag: "16-alpine"},
		},
		{
			name:    "whole image reference in the tag",
			fixture: "vulnerabilityreport_fullref_tag.json",
			want: Image{
				Name:   "valkey/valkey",
				Tag:    "9.0.0-alpine3.22",
				Digest: "sha256:bef37d06d4856710973ee31dd1eac1482e4c8e6e7b847f999ad25433e646587b",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ImageOf(loadFixture(t, tt.fixture), ""))
		})
	}
}

func TestImageOf_ImageReferenceOfTheContainer(t *testing.T) {
	const (
		digest = "sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317"
		newer  = "sha256:1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"
	)

	// Trivy Operator writes the last segment of the repository as the tag of a digest-only image.
	report := loadFixture(t, "vulnerabilityreport_dockerhub.json")
	require.NoError(t, unstructured.SetNestedField(report.Object, "postgres", "report", "artifact", "tag"))
	require.NoError(t, unstructured.SetNestedField(report.Object, digest, "report", "artifact", "digest"))

	asReported := Image{Name: "postgres", Tag: "postgres", Digest: digest}

	tests := []struct {
		name string
		ref  string
		want Image
	}{
		{name: "digest only, the digest of the report: no tag", ref: "postgres@" + digest, want: Image{Name: "postgres", Digest: digest}},
		{name: "digest only, another digest: the report", ref: "postgres@" + newer, want: asReported},
		{name: "tag only", ref: "postgres:16", want: asReported},
		{name: "tag and digest", ref: "postgres:16@" + digest, want: asReported},
		{name: "registry port without a tag", ref: "registry.example.com:5000/postgres", want: asReported},
		{name: "no tag and no digest", ref: "postgres", want: asReported},
		{name: "no reference", ref: "", want: asReported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ImageOf(report, tt.ref))
		})
	}
}

func TestImageOf_ReportWithoutADigestKeepsItsTag(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_dockerhub.json")

	assert.Equal(t, Image{Name: "postgres", Tag: "16-alpine"}, ImageOf(report, "postgres@sha256:abc"))
}

func TestTagOf(t *testing.T) {
	assert.Equal(t, "9.0", tagOf("docker.io/valkey/valkey:9.0"))
	assert.Equal(t, "9.0", tagOf("docker.io/valkey/valkey:9.0@sha256:abc"))
	assert.Empty(t, tagOf("registry.example.com:5000/valkey/valkey"))
	assert.Empty(t, tagOf("registry.example.com:5000/valkey/valkey@sha256:abc"))
}
