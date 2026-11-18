package trivy

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestShorten(t *testing.T) {
	t.Run("a value at the limit is unchanged", func(t *testing.T) {
		value := strings.Repeat("a", 200)

		assert.Equal(t, value, Shorten(value, 200))
	})

	t.Run("a shorter value is unchanged", func(t *testing.T) {
		assert.Equal(t, "ns/Deployment/app/web", Shorten("ns/Deployment/app/web", 200))
		assert.Empty(t, Shorten("", 200))
	})

	t.Run("a longer value is the start, a tilde and a hash of the full value", func(t *testing.T) {
		got := Shorten(strings.Repeat("a", 300), 200)

		assert.Equal(t, strings.Repeat("a", 187)+"~9835fa6bf4e2", got)
		assert.Len(t, got, 200)
	})

	t.Run("one character over the limit is shortened", func(t *testing.T) {
		got := Shorten(strings.Repeat("a", 201), 200)

		assert.Len(t, got, 200)
		assert.Contains(t, got, "~")
	})

	t.Run("the limit counts characters, not bytes", func(t *testing.T) {
		got := Shorten(strings.Repeat("é", 300), 100)

		assert.Equal(t, strings.Repeat("é", 87)+"~7250b66610f8", got)
		assert.Equal(t, 100, utf8.RuneCountInString(got))
		assert.True(t, utf8.ValidString(got))
	})

	t.Run("the same input gives the same output", func(t *testing.T) {
		value := strings.Repeat("x", 400)

		assert.Equal(t, Shorten(value, 255), Shorten(value, 255))
	})

	t.Run("values that share the start differ in the hash", func(t *testing.T) {
		a := Shorten(strings.Repeat("a", 300)+"1", 255)
		b := Shorten(strings.Repeat("a", 300)+"2", 255)

		assert.NotEqual(t, a, b)
		assert.Len(t, a, 255)
		assert.Len(t, b, 255)
	})
}
