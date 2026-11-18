package trivy

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"
)

const (
	// MaxServiceLen, MaxTitleLen, MaxVersionLen and MaxTagLen are the DefectDojo limits of the service, the test
	// title, the test version and a whole tag ("<key>:<value>"), in characters. The product name limit (255) is not
	// reached: the cluster name and the namespace are DNS labels.
	MaxServiceLen = 200
	MaxTitleLen   = 255
	MaxVersionLen = 100
	MaxTagLen     = 255
	// MaxBuildIDLen is the length the operator keeps the build_id of a test within. DefectDojo accepts 150; the
	// DefectDojo reimport form accepts 100.
	MaxBuildIDLen = 100

	// hashLen is the number of hex characters of the hash a shortened value ends with.
	hashLen = 12
)

// Shorten returns value when it has at most limit characters. A longer value becomes its start, "~" and the first
// 12 hex characters of the SHA-256 of the full value, limit characters in all. The same value always gives the
// same result.
func Shorten(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}

	sum := sha256.Sum256([]byte(value))
	suffix := "~" + hex.EncodeToString(sum[:])[:hashLen]

	keep := limit - len(suffix)
	runes := 0

	for i := range value {
		if runes == keep {
			return value[:i] + suffix
		}

		runes++
	}

	return value + suffix
}
