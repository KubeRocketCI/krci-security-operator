package trivy

import (
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// dockerHubHosts are the names under which Trivy Operator and image references address Docker Hub.
var dockerHubHosts = []string{"docker.io", "index.docker.io", "registry-1.docker.io"}

// Image is the image a report was produced for.
type Image struct {
	// Name is the normalised registry host and repository without tag or digest.
	Name   string
	Tag    string
	Digest string
}

// Version is the tag of the image, else "sha256:" and the first 12 characters of the digest, else "".
func (i Image) Version() string {
	if i.Tag != "" {
		return i.Tag
	}

	if i.Digest == "" {
		return ""
	}

	algo, hex, ok := strings.Cut(i.Digest, ":")
	if !ok {
		algo, hex = digestAlgo, i.Digest
	}

	return algo + ":" + hex[:min(len(hex), digestHexLen)]
}

// ImageOf returns the image a report was produced for: the registry, repository, tag and digest of the report.
// ref is the image reference of the container in the pod template of its workload, "" when it is not known.
// When ref has a digest and no tag, and the digest is the digest of the report, the tag of the report is dropped:
// Trivy Operator writes the last segment of the repository as the tag of a digest-only image.
func ImageOf(report *unstructured.Unstructured, ref string) Image {
	image := imageOfReport(report)

	if digest := digestOf(ref); digest != "" && digest == image.Digest && tagOf(ref) == "" {
		image.Tag = ""
	}

	return image
}

func imageOfReport(report *unstructured.Unstructured) Image {
	server, _, _ := unstructured.NestedString(report.Object, "report", "registry", "server")
	repository, _, _ := unstructured.NestedString(report.Object, "report", "artifact", "repository")
	tag, _, _ := unstructured.NestedString(report.Object, "report", "artifact", "tag")
	digest, _, _ := unstructured.NestedString(report.Object, "report", "artifact", "digest")

	ref := repository
	if server != "" {
		ref = server + "/" + repository
	}

	// Filesystem scans of some images put the whole image reference into the tag.
	if strings.Contains(tag, "/") {
		tag = tagOf(tag)
	}

	return Image{Name: NormalizeImage(ref), Tag: tag, Digest: digest}
}

// NormalizeImage returns the lower-case registry host and repository of an image reference
// without tag and digest. Docker Hub is written without its host and without the library/ namespace,
// so "docker.io/library/nginx:1.27", "index.docker.io/library/nginx" and "nginx" are the same image.
func NormalizeImage(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")

	if i := strings.LastIndex(ref, "/"); strings.Contains(ref[i+1:], ":") {
		ref = ref[:i+1+strings.Index(ref[i+1:], ":")]
	}

	ref = strings.ToLower(ref)

	for _, host := range dockerHubHosts {
		if rest, ok := strings.CutPrefix(ref, host+"/"); ok {
			return strings.TrimPrefix(rest, "library/")
		}
	}

	return ref
}

// digestOf returns the digest of an image reference, or an empty string when the reference has none.
func digestOf(ref string) string {
	_, digest, _ := strings.Cut(ref, "@")

	return digest
}

// tagOf returns the tag of an image reference, or an empty string when the reference has none.
// A colon before the last slash belongs to the registry port.
func tagOf(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	last := ref[strings.LastIndex(ref, "/")+1:]

	_, tag, _ := strings.Cut(last, ":")

	return tag
}
