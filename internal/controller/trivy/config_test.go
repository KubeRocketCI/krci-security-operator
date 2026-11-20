package trivy

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]

		return v, ok
	}
}

func requiredEnv() map[string]string {
	return map[string]string{
		EnvPodNamespace:         "krci-security",
		EnvDefectDojoSecretName: "defectdojo-credentials",
		EnvClusterName:          "prod-eu",
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig(lookupFrom(requiredEnv()))
	require.NoError(t, err)

	assert.Equal(t, Config{
		OperatorNamespace: "krci-security",
		SecretName:        "defectdojo-credentials",
		ProductType:       "KubeRocketCI",
		ClusterName:       "prod-eu",
		ComponentPrefixes: []string{"in-cluster-"},
		ResyncPeriod:      30 * time.Minute,
		Concurrency:       2,
		ReportKinds:       []string{"VulnerabilityReport", "ExposedSecretReport"},
	}, cfg)
}

func TestLoadConfig_Overrides(t *testing.T) {
	env := requiredEnv()
	env[EnvDefectDojoProductType] = "Acme"
	env[EnvClusterName] = "sandbox"
	env[EnvExcludeNamespaces] = " kube-*, trivy-system ,,"
	env[EnvComponentPrefixes] = "in-cluster-, core-"
	env[EnvResyncPeriod] = "10m"
	env[EnvConcurrency] = "5"
	env[EnvReportKinds] = "VulnerabilityReport"
	env[EnvNamespaceLabelTags] = " example.com/tenant, Team.Name ,,env"

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)

	assert.Equal(t, "Acme", cfg.ProductType)
	assert.Equal(t, "sandbox", cfg.ClusterName)
	assert.Equal(t, []string{"kube-*", "trivy-system"}, cfg.ExcludeNamespaces)
	assert.Equal(t, []string{"in-cluster-", "core-"}, cfg.ComponentPrefixes)
	assert.Equal(t, 10*time.Minute, cfg.ResyncPeriod)
	assert.Equal(t, 5, cfg.Concurrency)
	assert.Equal(t, []string{"VulnerabilityReport"}, cfg.ReportKinds)
	assert.Equal(t, []string{"example.com/tenant", "Team.Name", "env"}, cfg.NamespaceLabelTags,
		"the keys keep their case and their order")
}

func TestLoadConfig_DuplicateReportKindsAreIgnored(t *testing.T) {
	for value, want := range map[string][]string{
		"VulnerabilityReport,VulnerabilityReport": {"VulnerabilityReport"},
		"ExposedSecretReport, VulnerabilityReport,ExposedSecretReport,VulnerabilityReport": {
			"ExposedSecretReport", "VulnerabilityReport",
		},
	} {
		env := requiredEnv()
		env[EnvReportKinds] = value

		cfg, err := LoadConfig(lookupFrom(env))
		require.NoError(t, err, value)
		assert.Equal(t, want, cfg.ReportKinds, "the first occurrence is kept, in order")
	}
}

func TestLoadConfig_EmptyListsStayEmpty(t *testing.T) {
	env := requiredEnv()
	env[EnvComponentPrefixes] = ""
	env[EnvNamespaceLabelTags] = " , "

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)
	assert.Empty(t, cfg.ComponentPrefixes)
	assert.Empty(t, cfg.NamespaceLabelTags)
}

// labelKeyOfLength returns a valid label key of n characters: a prefix of DNS labels and a name of 20 characters.
func labelKeyOfLength(t *testing.T, n int) string {
	t.Helper()

	const name = "nnnnnnnnnnnnnnnnnnnn"

	var labels []string

	left := n - len(name) - len("/")
	for ; left > validation.DNS1123LabelMaxLength; left -= validation.DNS1123LabelMaxLength + len(".") {
		labels = append(labels, strings.Repeat("a", validation.DNS1123LabelMaxLength))
	}

	key := strings.Join(append(labels, strings.Repeat("a", left)), ".") + "/" + name

	require.Empty(t, validation.IsQualifiedName(key), "a valid label key")
	require.Len(t, key, n)

	return key
}

func TestLoadConfig_NamespaceLabelTagsAcceptLabelKeys(t *testing.T) {
	keys := []string{"team", "Team.Name", "example.com/tenant", "a.b-c/d_E.f", "n", labelKeyOfLength(t, trivy.MaxNamespaceLabelKeyLen)}

	for _, key := range keys {
		env := requiredEnv()
		env[EnvNamespaceLabelTags] = key

		cfg, err := LoadConfig(lookupFrom(env))
		require.NoError(t, err, key)
		assert.Equal(t, []string{key}, cfg.NamespaceLabelTags)
	}

	env := requiredEnv()
	env[EnvNamespaceLabelTags] = strings.Join(keys, ",")

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err, "no bound on the number of keys")
	assert.Equal(t, keys, cfg.NamespaceLabelTags)
}

func TestLoadConfig_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"missing namespace", func(e map[string]string) { delete(e, EnvPodNamespace) }, EnvPodNamespace},
		{"missing secret name", func(e map[string]string) { delete(e, EnvDefectDojoSecretName) }, EnvDefectDojoSecretName},
		{"missing cluster name", func(e map[string]string) { delete(e, EnvClusterName) }, EnvClusterName + " is required"},
		{"blank cluster name", func(e map[string]string) { e[EnvClusterName] = "  " }, EnvClusterName + " is required"},
		{"bad duration", func(e map[string]string) { e[EnvResyncPeriod] = "soon" }, EnvResyncPeriod},
		{"zero duration", func(e map[string]string) { e[EnvResyncPeriod] = "0s" }, "must be at least 1m0s"},
		{"duration just below the minimum", func(e map[string]string) { e[EnvResyncPeriod] = "59s" }, "must be at least 1m0s, got 59s"},
		{"bad concurrency", func(e map[string]string) { e[EnvConcurrency] = "many" }, EnvConcurrency},
		{"zero concurrency", func(e map[string]string) { e[EnvConcurrency] = "0" }, "at least 1"},
		{"no report kinds", func(e map[string]string) { e[EnvReportKinds] = "" }, "at least one report kind"},
		{"unknown report kind", func(e map[string]string) { e[EnvReportKinds] = "ConfigAuditReport" }, "unsupported report kind"},
		{"cluster name with upper case", func(e map[string]string) { e[EnvClusterName] = "Prod" }, "lowercase RFC 1123"},
		{"cluster name with underscore", func(e map[string]string) { e[EnvClusterName] = "prod_1" }, "lowercase RFC 1123"},
		{"cluster name with dot", func(e map[string]string) { e[EnvClusterName] = "a.b" }, "lowercase RFC 1123"},
		{"cluster name too long", func(e map[string]string) { e[EnvClusterName] = strings.Repeat("a", 64) }, "lowercase RFC 1123"},
		{"product type with comma", func(e map[string]string) { e[EnvDefectDojoProductType] = "a,b" }, "no comma"},
		{"bad glob", func(e map[string]string) { e[EnvExcludeNamespaces] = "kube-[" }, "invalid glob"},
		{"label key with a space", func(e map[string]string) { e[EnvNamespaceLabelTags] = "bad key" }, EnvNamespaceLabelTags + `: "bad key" is not a valid label key`},
		{"label key with two slashes", func(e map[string]string) { e[EnvNamespaceLabelTags] = "a/b/c" }, `"a/b/c" is not a valid label key`},
		{"label key that starts with a hyphen", func(e map[string]string) { e[EnvNamespaceLabelTags] = "team,-env" }, `"-env" is not a valid label key`},
		{"label key with an upper case prefix", func(e map[string]string) { e[EnvNamespaceLabelTags] = "Example.com/team" }, "is not a valid label key"},
		{"label key whose tag does not fit", func(e map[string]string) {
			e[EnvNamespaceLabelTags] = labelKeyOfLength(t, trivy.MaxNamespaceLabelKeyLen+1)
		}, "is too long"},
		{"repeated label key", func(e map[string]string) { e[EnvNamespaceLabelTags] = "team,env,team" }, `label keys "team" and "team" give the same tag key "k8s-ns-label.team"`},
		{"label keys that differ in case only", func(e map[string]string) { e[EnvNamespaceLabelTags] = "Team,team" }, `label keys "Team" and "team" give the same tag key "k8s-ns-label.team"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := requiredEnv()
			tt.mutate(env)

			_, err := LoadConfig(lookupFrom(env))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestConfigValidate_ReportsAllViolations(t *testing.T) {
	err := Config{}.Validate()
	require.Error(t, err)

	for _, want := range []string{EnvPodNamespace, EnvDefectDojoSecretName, EnvClusterName, EnvResyncPeriod, EnvConcurrency, EnvReportKinds} {
		assert.Contains(t, err.Error(), want)
	}
}

// validConfig returns the configuration of the required variables only.
func validConfig(t *testing.T) Config {
	t.Helper()

	cfg, err := LoadConfig(lookupFrom(requiredEnv()))
	require.NoError(t, err)

	return cfg
}

func TestConfigValidate_ReportsEveryInvalidLabelKey(t *testing.T) {
	cfg := validConfig(t)
	cfg.NamespaceLabelTags = []string{"ok", "example.com/other"}
	require.NoError(t, cfg.Validate())

	cfg.NamespaceLabelTags = []string{"bad key", "ok", "-bad", "OK"}

	err := cfg.Validate()
	require.Error(t, err)

	for _, want := range []string{`"bad key" is not a valid label key`, `"-bad" is not a valid label key`, `"ok" and "OK" give the same tag key`} {
		assert.Contains(t, err.Error(), want)
	}
}

func TestConfigValidate_NamesAndPrefixes(t *testing.T) {
	cfg := validConfig(t)
	cfg.ProductType = ""
	require.ErrorContains(t, cfg.Validate(), "non-empty")

	cfg = validConfig(t)
	cfg.ComponentPrefixes = []string{"ok-", "bad,prefix"}
	require.ErrorContains(t, cfg.Validate(), "prefix")

	cfg = validConfig(t)
	cfg.ClusterName = ""
	require.ErrorContains(t, cfg.Validate(), EnvClusterName+" is required")

	cfg = validConfig(t)
	cfg.ClusterName = "prod-eu-1"
	require.NoError(t, cfg.Validate())
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv(EnvPodNamespace, "ns")
	t.Setenv(EnvDefectDojoSecretName, "s")
	t.Setenv(EnvClusterName, "c")

	cfg, err := LoadConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "ns", cfg.OperatorNamespace)
}

func TestLoadConfig_MinimumResyncPeriodIsAccepted(t *testing.T) {
	env := requiredEnv()
	env[EnvResyncPeriod] = "1m"

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)
	assert.Equal(t, minResyncPeriod, cfg.ResyncPeriod)
}
