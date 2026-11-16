package trivy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// Environment variables of the Trivy module. The chart sets them from its values.
const (
	EnvPodNamespace           = "POD_NAMESPACE"
	EnvDefectDojoSecretName   = "DEFECTDOJO_SECRET_NAME"
	EnvDefectDojoProductType  = "DEFECTDOJO_PRODUCT_TYPE"
	EnvDefectDojoPlatformProd = "DEFECTDOJO_PLATFORM_PRODUCT"
	EnvClusterName            = "CLUSTER_NAME"
	EnvScopeStage             = "SCOPE_STAGE"
	EnvScopeTenant            = "SCOPE_TENANT"
	EnvScopePlatform          = "SCOPE_PLATFORM"
	EnvExcludeNamespaces      = "EXCLUDE_NAMESPACES"
	EnvComponentPrefixes      = "COMPONENT_PREFIXES"
	EnvResyncPeriod           = "RESYNC_PERIOD"
	EnvConcurrency            = "CONCURRENCY"
	EnvReportKinds            = "REPORT_KINDS"
)

// Keys of the credentials Secret.
const (
	SecretKeyURL   = "url"
	SecretKeyToken = "token"
)

const (
	defaultProductType     = "KubeRocketCI"
	defaultPlatformProduct = "platform"
	defaultClusterName     = "in-cluster"
	defaultComponentPrefix = "in-cluster-"
	defaultResyncPeriod    = 30 * time.Minute
	defaultConcurrency     = 2
	listSeparator          = ","
	errInvalidConfig       = "invalid configuration"
)

// Scopes switches the namespace scopes on and off.
type Scopes struct {
	Stage    bool
	Tenant   bool
	Platform bool
}

// Config is the configuration of the Trivy module.
type Config struct {
	// OperatorNamespace is the namespace that holds the credentials Secret.
	OperatorNamespace string
	// SecretName is the credentials Secret with the keys "url" and "token".
	SecretName string
	// ProductType is the DefectDojo product type of the created products.
	ProductType string
	// PlatformProduct is the product of the platform scope.
	PlatformProduct string
	// ClusterName marks the tests of this cluster with the tag "krci-cluster:<ClusterName>".
	ClusterName string
	Scopes      Scopes
	// ExcludeNamespaces holds glob patterns of namespaces that are skipped.
	ExcludeNamespaces []string
	// ComponentPrefixes are stripped from the Argo CD application name to derive the component tag.
	ComponentPrefixes []string
	// ResyncPeriod is the interval of the periodic requeue of a namespace.
	ResyncPeriod time.Duration
	// Concurrency is the number of namespaces reconciled in parallel.
	Concurrency int
	// ReportKinds lists the Trivy report kinds that are imported.
	ReportKinds []string
}

// LoadConfigFromEnv reads the configuration from the process environment and validates it.
func LoadConfigFromEnv() (Config, error) {
	return LoadConfig(os.LookupEnv)
}

// LoadConfig reads the configuration through lookup, applies the defaults and validates the result.
// A variable that is set but empty keeps the list variables empty and takes the default for the others.
func LoadConfig(lookup func(string) (string, bool)) (Config, error) {
	var errs []error

	get := func(key, def string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}

		return def
	}

	list := func(key string, def []string) []string {
		v, ok := lookup(key)
		if !ok {
			return def
		}

		return splitList(v)
	}

	boolean := func(key string) bool {
		raw := get(key, "true")

		b, err := strconv.ParseBool(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
		}

		return b
	}

	cfg := Config{
		OperatorNamespace: get(EnvPodNamespace, ""),
		SecretName:        get(EnvDefectDojoSecretName, ""),
		ProductType:       get(EnvDefectDojoProductType, defaultProductType),
		PlatformProduct:   get(EnvDefectDojoPlatformProd, defaultPlatformProduct),
		ClusterName:       get(EnvClusterName, defaultClusterName),
		Scopes: Scopes{
			Stage:    boolean(EnvScopeStage),
			Tenant:   boolean(EnvScopeTenant),
			Platform: boolean(EnvScopePlatform),
		},
		ExcludeNamespaces: list(EnvExcludeNamespaces, nil),
		ComponentPrefixes: list(EnvComponentPrefixes, []string{defaultComponentPrefix}),
		ReportKinds:       list(EnvReportKinds, slices.Clone(trivy.ReportKinds)),
		ResyncPeriod:      defaultResyncPeriod,
		Concurrency:       defaultConcurrency,
	}

	if raw := get(EnvResyncPeriod, ""); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvResyncPeriod, err))
		} else {
			cfg.ResyncPeriod = d
		}
	}

	if raw := get(EnvConcurrency, ""); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvConcurrency, err))
		} else {
			cfg.Concurrency = n
		}
	}

	if len(errs) > 0 {
		return Config{}, fmt.Errorf("%s: %w", errInvalidConfig, errors.Join(errs...))
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate reports every violated constraint of the configuration.
func (c Config) Validate() error {
	var errs []error

	if c.OperatorNamespace == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvPodNamespace))
	}

	if c.SecretName == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvDefectDojoSecretName))
	}

	// The cluster name is part of the "krci-cluster" tag that decides which tests the operator owns.
	if msgs := validation.IsDNS1123Label(c.ClusterName); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("%s must be a lowercase RFC 1123 DNS label, got %q: %s",
			EnvClusterName, c.ClusterName, strings.Join(msgs, "; ")))
	}

	// The names end up in DefectDojo, where a comma separates tags.
	for _, f := range []struct{ env, value string }{
		{EnvDefectDojoProductType, c.ProductType},
		{EnvDefectDojoPlatformProd, c.PlatformProduct},
	} {
		if f.value == "" || strings.Contains(f.value, listSeparator) {
			errs = append(errs, fmt.Errorf("%s must be non-empty and contain no comma, got %q", f.env, f.value))
		}
	}

	for _, p := range c.ComponentPrefixes {
		if strings.Contains(p, listSeparator) {
			errs = append(errs, fmt.Errorf("%s: prefix %q must contain no comma", EnvComponentPrefixes, p))
		}
	}

	if c.ResyncPeriod <= 0 {
		errs = append(errs, fmt.Errorf("%s must be positive, got %s", EnvResyncPeriod, c.ResyncPeriod))
	}

	if c.Concurrency < 1 {
		errs = append(errs, fmt.Errorf("%s must be at least 1, got %d", EnvConcurrency, c.Concurrency))
	}

	if len(c.ReportKinds) == 0 {
		errs = append(errs, fmt.Errorf("%s must list at least one report kind", EnvReportKinds))
	}

	for _, k := range c.ReportKinds {
		if !slices.Contains(trivy.ReportKinds, k) {
			errs = append(errs, fmt.Errorf("%s: unsupported report kind %q", EnvReportKinds, k))
		}
	}

	for _, p := range c.ExcludeNamespaces {
		if _, err := path.Match(p, ""); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid glob %q: %w", EnvExcludeNamespaces, p, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", errInvalidConfig, errors.Join(errs...))
	}

	return nil
}

func splitList(v string) []string {
	var out []string

	for _, item := range strings.Split(v, listSeparator) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}

	return out
}
