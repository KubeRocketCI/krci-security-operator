package trivy

import "k8s.io/apimachinery/pkg/util/validation"

// MaxLabelKeyLen is the longest label key whose tag fits MaxTagLen with any label value.
const MaxLabelKeyLen = MaxTagLen - len(":") - validation.LabelValueMaxLength

// LabelTagKey is the tag key of a label key: the key in lower case, the case DefectDojo stores the tags of a test in.
func LabelTagKey(labelKey string) string { return TagSafe(labelKey) }

// LabelTags returns the tag "<label key>:<value>" of each of the keys that labels holds with a value, in the order of
// keys. The value is made tag-safe and shortened as in every tag. A key without a label, and a label with an empty
// value, give no tag.
func LabelTags(keys []string, labels map[string]string) []string {
	var tags []string

	for _, key := range keys {
		if t := tag(LabelTagKey(key), labels[key]); t != "" {
			tags = append(tags, t)
		}
	}

	return tags
}
