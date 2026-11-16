package trivy

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig(lookupFrom(requiredEnv()))
	require.NoError(t, err)

	assert.Equal(t, Config{
		OperatorNamespace: "krci-security",
		SecretName:        "defectdojo-credentials",
		ProductType:       "KubeRocketCI",
		PlatformProduct:   "platform",
		ClusterName:       "in-cluster",
		Scopes:            Scopes{Stage: true, Tenant: true, Platform: true},
		ComponentPrefixes: []string{"in-cluster-"},
		ResyncPeriod:      30 * time.Minute,
		Concurrency:       2,
		ReportKinds:       []string{"VulnerabilityReport", "ExposedSecretReport"},
	}, cfg)
}

func TestLoadConfig_Overrides(t *testing.T) {
	env := requiredEnv()
	env[EnvDefectDojoProductType] = "Acme"
	env[EnvDefectDojoPlatformProd] = "infra"
	env[EnvClusterName] = "sandbox"
	env[EnvScopeStage] = "true"
	env[EnvScopeTenant] = "false"
	env[EnvScopePlatform] = "0"
	env[EnvExcludeNamespaces] = " kube-*, trivy-system ,,"
	env[EnvComponentPrefixes] = "in-cluster-, core-"
	env[EnvResyncPeriod] = "10m"
	env[EnvConcurrency] = "5"
	env[EnvReportKinds] = "VulnerabilityReport"

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)

	assert.Equal(t, "Acme", cfg.ProductType)
	assert.Equal(t, "infra", cfg.PlatformProduct)
	assert.Equal(t, "sandbox", cfg.ClusterName)
	assert.Equal(t, Scopes{Stage: true, Tenant: false, Platform: false}, cfg.Scopes)
	assert.Equal(t, []string{"kube-*", "trivy-system"}, cfg.ExcludeNamespaces)
	assert.Equal(t, []string{"in-cluster-", "core-"}, cfg.ComponentPrefixes)
	assert.Equal(t, 10*time.Minute, cfg.ResyncPeriod)
	assert.Equal(t, 5, cfg.Concurrency)
	assert.Equal(t, []string{"VulnerabilityReport"}, cfg.ReportKinds)
}

func TestLoadConfig_EmptyListsStayEmpty(t *testing.T) {
	env := requiredEnv()
	env[EnvComponentPrefixes] = ""

	cfg, err := LoadConfig(lookupFrom(env))
	require.NoError(t, err)
	assert.Empty(t, cfg.ComponentPrefixes)
}

func TestLoadConfig_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"missing namespace", func(e map[string]string) { delete(e, EnvPodNamespace) }, EnvPodNamespace},
		{"missing secret name", func(e map[string]string) { delete(e, EnvDefectDojoSecretName) }, EnvDefectDojoSecretName},
		{"bad bool", func(e map[string]string) { e[EnvScopeTenant] = "maybe" }, EnvScopeTenant},
		{"bad duration", func(e map[string]string) { e[EnvResyncPeriod] = "soon" }, EnvResyncPeriod},
		{"zero duration", func(e map[string]string) { e[EnvResyncPeriod] = "0s" }, "must be positive"},
		{"bad concurrency", func(e map[string]string) { e[EnvConcurrency] = "many" }, EnvConcurrency},
		{"zero concurrency", func(e map[string]string) { e[EnvConcurrency] = "0" }, "at least 1"},
		{"no report kinds", func(e map[string]string) { e[EnvReportKinds] = "" }, "at least one report kind"},
		{"unknown report kind", func(e map[string]string) { e[EnvReportKinds] = "ConfigAuditReport" }, "unsupported report kind"},
		{"cluster name with upper case", func(e map[string]string) { e[EnvClusterName] = "Prod" }, "lowercase RFC 1123"},
		{"cluster name with underscore", func(e map[string]string) { e[EnvClusterName] = "prod_1" }, "lowercase RFC 1123"},
		{"cluster name with dot", func(e map[string]string) { e[EnvClusterName] = "a.b" }, "lowercase RFC 1123"},
		{"cluster name too long", func(e map[string]string) { e[EnvClusterName] = strings.Repeat("a", 64) }, "lowercase RFC 1123"},
		{"product type with comma", func(e map[string]string) { e[EnvDefectDojoProductType] = "a,b" }, "no comma"},
		{"platform product with comma", func(e map[string]string) { e[EnvDefectDojoPlatformProd] = "a,b" }, "no comma"},
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

	for _, want := range []string{EnvPodNamespace, EnvDefectDojoSecretName, EnvResyncPeriod, EnvConcurrency, EnvReportKinds} {
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
	cfg.PlatformProduct = ""
	require.ErrorContains(t, cfg.Validate(), "non-empty")

	cfg = valid()
	cfg.ComponentPrefixes = []string{"ok-", "bad,prefix"}
	require.ErrorContains(t, cfg.Validate(), "prefix")

	cfg = valid()
	cfg.ClusterName = ""
	require.ErrorContains(t, cfg.Validate(), EnvClusterName)

	cfg = valid()
	cfg.ClusterName = "prod-eu-1"
	require.NoError(t, cfg.Validate())
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv(EnvPodNamespace, "ns")
	t.Setenv(EnvDefectDojoSecretName, "s")

	cfg, err := LoadConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "ns", cfg.OperatorNamespace)
}
