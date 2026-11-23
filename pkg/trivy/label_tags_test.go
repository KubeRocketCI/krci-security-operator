package trivy

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"
)

const tenantKey = "app.edp.epam.com/tenant"

func TestLabelTags(t *testing.T) {
	tests := map[string]struct {
		keys   []string
		labels map[string]string
		want   []string
	}{
		"a listed label gives <key>:<value>": {
			keys:   []string{tenantKey},
			labels: map[string]string{tenantKey: "krci-demo"},
			want:   []string{"app.edp.epam.com/tenant:krci-demo"},
		},
		"the tags follow the order of the keys": {
			keys:   []string{"b", "a", "c"},
			labels: map[string]string{"a": "1", "b": "2", "c": "3"},
			want:   []string{"b:2", "a:1", "c:3"},
		},
		"a label that is not listed gives no tag": {
			keys:   []string{"a"},
			labels: map[string]string{"a": "1", "b": "2"},
			want:   []string{"a:1"},
		},
		"a listed key without a label gives no tag": {
			keys:   []string{"a", "b"},
			labels: map[string]string{"a": "1"},
			want:   []string{"a:1"},
		},
		"a label with an empty value gives no tag": {
			keys:   []string{"a", "b"},
			labels: map[string]string{"a": "", "b": "2"},
			want:   []string{"b:2"},
		},
		"no keys give no tag": {
			labels: map[string]string{"a": "1"},
		},
		"no labels give no tag": {
			keys: []string{"a"},
		},
		"the key and the value are lower case": {
			keys:   []string{"Team.Name"},
			labels: map[string]string{"Team.Name": "Alpha-Team"},
			want:   []string{"team.name:alpha-team"},
		},
		"the value is tag-safe": {
			keys:   []string{"a"},
			labels: map[string]string{"a": "Dev Team, 'x'"},
			want:   []string{"a:dev-team---x-"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, LabelTags(tt.keys, tt.labels))
		})
	}
}

func TestLabelTags_TagOverTheLimitIsShortenedKeepingItsKey(t *testing.T) {
	value := strings.Repeat("v", 300)

	got := LabelTags([]string{"team"}, map[string]string{"team": value})

	require.Len(t, got, 1)
	assert.Len(t, got[0], MaxTagLen)
	assert.True(t, strings.HasPrefix(got[0], "team:vvv"))
	assert.Equal(t, "team:"+Shorten(value, MaxTagLen-len("team:")), got[0], "the rule of every other tag")
	assert.Equal(t, got, LabelTags([]string{"team"}, map[string]string{"team": value}), "the same input gives the same tag")
}

func TestLabelTags_KeyOfMaxLabelKeyLenFitsWithAnyLabelValue(t *testing.T) {
	key := strings.Repeat("k", MaxLabelKeyLen)
	value := strings.Repeat("v", validation.LabelValueMaxLength)

	got := LabelTags([]string{key}, map[string]string{key: value})

	assert.Equal(t, []string{key + ":" + value}, got)
	assert.Len(t, got[0], MaxTagLen)
}

func TestReservedTagKeys_AreTheTagKeysTheOperatorWrites(t *testing.T) {
	test := newReimport(testTarget(), loadFixture(t, "vulnerabilityreport_replicaset.json"), Workload{"deployment", "app"}, "x")

	tags := slices.Concat(test.Tags, ProductTags("c", "ns"))
	written := make([]string, 0, len(tags))

	for _, tag := range tags {
		key, _, _ := strings.Cut(tag, ":")
		written = append(written, key)
	}

	slices.Sort(written)

	assert.Equal(t, slices.Sorted(slices.Values(ReservedTagKeys)), slices.Compact(written),
		"the keys of the tags of a test and a product that have every tag")
}

func TestReimportTags_LabelTagsComeAfterTheTagsOfTheOperator(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	workload := Workload{"deployment", "test-go-app"}
	plain := newReimport(testTarget(), report, workload, "go-app")

	got := NewReimport(testTarget(), report.GetKind(), report, workload, "go-app", ReportImage(report),
		[]string{"team:a", "app.edp.epam.com/codebase:shop"})

	assert.Equal(t, append(slices.Clone(plain.Tags), "team:a", "app.edp.epam.com/codebase:shop"), got.Tags)
	assert.Equal(t, plain.TestTitle, got.TestTitle)
	assert.Equal(t, plain.Service, got.Service)
	assert.Equal(t, plain.Version, got.Version)
}

func TestUploadMarker_ChangesWithTheLabelTagsOfTheWorkload(t *testing.T) {
	report := loadFixture(t, "vulnerabilityreport_replicaset.json")
	report.SetUID("uid")
	report.SetResourceVersion("1")

	workload := Workload{"deployment", "test-go-app"}
	marker := func(labelTags ...string) string {
		return NewReimport(testTarget(), report.GetKind(), report, workload, "go-app", ReportImage(report), labelTags).
			UploadMarker(report)
	}

	assert.Equal(t, marker(), marker(), "the same request gives the same marker")
	assert.NotEqual(t, marker(), marker("team:a"), "a tag is added")
	assert.NotEqual(t, marker("team:a"), marker("team:b"), "a value changes")
	assert.NotEqual(t, marker("team:a"), marker(), "a tag is removed")
}

func TestWithProductTags_LabelTags(t *testing.T) {
	keys := []string{tenantKey, "env"}
	labels := map[string]string{tenantKey: "krci", "env": "dev", "unlisted": "x"}

	tests := []struct {
		name        string
		have        []string
		keys        []string
		labels      map[string]string
		want        []string
		wantChanged bool
	}{
		{
			name: "the tag of each listed label is added", keys: keys, labels: labels,
			want:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
			wantChanged: true,
		},
		{
			name: "a product that has the tags is unchanged", keys: keys, labels: labels,
			have: []string{"env:dev", "app.edp.epam.com/tenant:krci", "k8s-namespace:ns", "k8s-cluster:c1"},
			want: []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
		},
		{
			name: "a changed value is corrected", keys: keys, labels: labels,
			have:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:old", "env:dev"},
			want:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
			wantChanged: true,
		},
		{
			name: "the tag of a removed label is removed", keys: keys, labels: map[string]string{"env": "dev"},
			have:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
			want:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "env:dev"},
			wantChanged: true,
		},
		{
			name: "the tag of a label with an empty value is removed", keys: keys, labels: map[string]string{"env": ""},
			have:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "env:dev"},
			want:        []string{"k8s-cluster:c1", "k8s-namespace:ns"},
			wantChanged: true,
		},
		{
			name: "every tag of a listed key is replaced by one", keys: keys, labels: labels,
			have:        []string{"env:a", "env:b", "k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci"},
			want:        []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
			wantChanged: true,
		},
		{
			name: "the tags of other keys are kept", keys: []string{"env"}, labels: labels,
			have:        []string{"owner:team-a", "app.edp.epam.com/tenant:old", "env-name:x", "environment:y"},
			want:        []string{"owner:team-a", "app.edp.epam.com/tenant:old", "env-name:x", "environment:y", "k8s-cluster:c1", "k8s-namespace:ns", "env:dev"},
			wantChanged: true,
		},
		{
			name: "no key is listed: the label tags are kept", keys: nil, labels: labels,
			have: []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
			want: []string{"k8s-cluster:c1", "k8s-namespace:ns", "app.edp.epam.com/tenant:krci", "env:dev"},
		},
		{
			name: "the key is compared in lower case", keys: []string{"Team.Name"}, labels: map[string]string{"Team.Name": "Alpha"},
			have: []string{"k8s-cluster:c1", "k8s-namespace:ns", "team.name:alpha"},
			want: []string{"k8s-cluster:c1", "k8s-namespace:ns", "team.name:alpha"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := WithProductTags(tt.have, "c1", "ns", tt.keys, tt.labels)

			assert.ElementsMatch(t, tt.want, got)
			assert.Equal(t, tt.wantChanged, changed)
		})
	}
}
