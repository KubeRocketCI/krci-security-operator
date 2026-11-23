package trivy

import (
	"slices"
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

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)

	assert.Equal(t, "Acme", cfg.ProductType)
	assert.Equal(t, "sandbox", cfg.ClusterName)
	assert.Equal(t, []string{"kube-*", "trivy-system"}, cfg.ExcludeNamespaces)
	assert.Equal(t, []string{"in-cluster-", "core-"}, cfg.ComponentPrefixes)
	assert.Equal(t, 10*time.Minute, cfg.ResyncPeriod)
	assert.Equal(t, 5, cfg.Concurrency)
	assert.Equal(t, []string{"VulnerabilityReport"}, cfg.ReportKinds)
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
	env[EnvWorkloadLabelTags] = ""

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)
	assert.Empty(t, cfg.ComponentPrefixes)
	assert.Empty(t, cfg.NamespaceLabelTags)
	assert.Empty(t, cfg.WorkloadLabelTags)
}

// labelTagSettings are the two label allow-lists: the variable and the field of Config each fills.
var labelTagSettings = map[string]func(Config) []string{
	EnvNamespaceLabelTags: func(c Config) []string { return c.NamespaceLabelTags },
	EnvWorkloadLabelTags:  func(c Config) []string { return c.WorkloadLabelTags },
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

func TestLoadConfig_LabelTagsKeepTheKeysInTheirCaseAndOrder(t *testing.T) {
	for name, field := range labelTagSettings {
		t.Run(name, func(t *testing.T) {
			env := requiredEnv()
			env[name] = " app.edp.epam.com/tenant, Team.Name ,,env"

			cfg, err := LoadConfig(lookupFrom(env))
			require.NoError(t, err)

			assert.Equal(t, []string{"app.edp.epam.com/tenant", "Team.Name", "env"}, field(cfg))
		})
	}
}

func TestLoadConfig_LabelTagsAreSeparateSettings(t *testing.T) {
	env := requiredEnv()
	env[EnvNamespaceLabelTags] = "env,team"
	env[EnvWorkloadLabelTags] = "team"

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err, "the same key may be listed for the namespace and for the workload")

	assert.Equal(t, []string{"env", "team"}, cfg.NamespaceLabelTags)
	assert.Equal(t, []string{"team"}, cfg.WorkloadLabelTags)
}

func TestLoadConfig_LabelTagsAcceptLabelKeys(t *testing.T) {
	keys := []string{"team", "Team.Name", "app.edp.epam.com/tenant", "a.b-c/d_E.f", "n", labelKeyOfLength(t, trivy.MaxLabelKeyLen)}

	for name, field := range labelTagSettings {
		t.Run(name, func(t *testing.T) {
			for _, key := range keys {
				env := requiredEnv()
				env[name] = key

				cfg, err := LoadConfig(lookupFrom(env))
				require.NoError(t, err, key)
				assert.Equal(t, []string{key}, field(cfg))
			}

			env := requiredEnv()
			env[name] = strings.Join(keys, ",")

			cfg, err := LoadConfig(lookupFrom(env))
			require.NoError(t, err, "no bound on the number of keys")
			assert.Equal(t, keys, field(cfg))
		})
	}
}

func TestLoadConfig_LabelTagErrors(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"a key with a space", "bad key", `"bad key" is not a valid label key`},
		{"a key with two slashes", "a/b/c", `"a/b/c" is not a valid label key`},
		{"a key that starts with a hyphen", "team,-env", `"-env" is not a valid label key`},
		{"a key with an upper case prefix", "Example.com/team", `"Example.com/team" is not a valid label key`},
		{"a key with a colon", "a:b", `"a:b" is not a valid label key`},
		{"a key whose tag does not fit", labelKeyOfLength(t, trivy.MaxLabelKeyLen+1), "is too long"},
		{"a repeated key", "team,env,team", `label keys "team" and "team" give the same tag key "team"`},
		{"keys that differ in case only", "Team,team", `label keys "Team" and "team" give the same tag key "team"`},
	}

	for name := range labelTagSettings {
		for _, tt := range tests {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				env := requiredEnv()
				env[name] = tt.value

				_, err := LoadConfig(lookupFrom(env))
				require.Error(t, err)
				assert.Contains(t, err.Error(), name+": ")
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	}
}

func TestLoadConfig_LabelKeyOfATagTheOperatorWritesStopsTheStart(t *testing.T) {
	for name := range labelTagSettings {
		for _, key := range slices.Concat(trivy.ReservedTagKeys, []string{"App", "K8s-Cluster"}) {
			t.Run(name+"/"+key, func(t *testing.T) {
				env := requiredEnv()
				env[name] = "team," + key + ",env"

				_, err := LoadConfig(lookupFrom(env))
				require.Error(t, err)
				assert.Contains(t, err.Error(), name+`: label key "`+key+`" gives the tag key "`+strings.ToLower(key)+`"`)
			})
		}
	}
}

func TestLoadConfig_LabelKeyThatContainsAReservedKeyIsAccepted(t *testing.T) {
	for name := range labelTagSettings {
		env := requiredEnv()
		env[name] = "app.kubernetes.io/name,k8s-cluster-name,my-app,example.com/app,report-kind.example.com/x"

		_, err := LoadConfig(lookupFrom(env))
		require.NoError(t, err, name)
	}
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

func TestConfigValidate_ReportsEveryInvalidLabelKeyOfBothSettings(t *testing.T) {
	cfg, err := LoadConfig(lookupFrom(requiredEnv()))
	require.NoError(t, err)

	cfg.NamespaceLabelTags = []string{"ok", "example.com/other"}
	cfg.WorkloadLabelTags = []string{"fine"}
	require.NoError(t, cfg.Validate())

	cfg.NamespaceLabelTags = []string{"bad key", "ok", "-bad", "OK"}
	cfg.WorkloadLabelTags = []string{"app", "x"}

	err = cfg.Validate()
	require.Error(t, err)

	for _, want := range []string{
		EnvNamespaceLabelTags + `: "bad key" is not a valid label key`,
		EnvNamespaceLabelTags + `: "-bad" is not a valid label key`,
		EnvNamespaceLabelTags + `: label keys "ok" and "OK" give the same tag key "ok"`,
		EnvWorkloadLabelTags + `: label key "app" gives the tag key "app"`,
	} {
		assert.Contains(t, err.Error(), want)
	}
}

func TestConfigValidate_NamesAndPrefixes(t *testing.T) {
	valid := func() Config {
		cfg, err := LoadConfig(lookupFrom(requiredEnv()))
		require.NoError(t, err)

		return cfg
	}

	cfg := valid()
	cfg.ProductType = ""
	require.ErrorContains(t, cfg.Validate(), "non-empty")

	cfg = valid()
	cfg.ComponentPrefixes = []string{"ok-", "bad,prefix"}
	require.ErrorContains(t, cfg.Validate(), "prefix")

	cfg = valid()
	cfg.ClusterName = ""
	require.ErrorContains(t, cfg.Validate(), EnvClusterName+" is required")

	cfg = valid()
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

func TestLoadConfigFromEnv_ALabelKeyOfATagTheOperatorWritesIsNamedInTheError(t *testing.T) {
	t.Setenv(EnvPodNamespace, "ns")
	t.Setenv(EnvDefectDojoSecretName, "s")
	t.Setenv(EnvClusterName, "c")
	t.Setenv(EnvWorkloadLabelTags, "team,report-kind")

	_, err := LoadConfigFromEnv()

	require.Error(t, err, "main exits with this error")
	assert.Contains(t, err.Error(), `WORKLOAD_LABEL_TAGS: label key "report-kind"`)
}

func TestLoadConfig_MinimumResyncPeriodIsAccepted(t *testing.T) {
	env := requiredEnv()
	env[EnvResyncPeriod] = "1m"

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)
	assert.Equal(t, minResyncPeriod, cfg.ResyncPeriod)
}
