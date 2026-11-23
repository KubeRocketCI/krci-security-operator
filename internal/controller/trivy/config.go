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
	EnvPodNamespace          = "POD_NAMESPACE"
	EnvDefectDojoSecretName  = "DEFECTDOJO_SECRET_NAME"
	EnvDefectDojoProductType = "DEFECTDOJO_PRODUCT_TYPE"
	EnvClusterName           = "CLUSTER_NAME"
	EnvExcludeNamespaces     = "EXCLUDE_NAMESPACES"
	EnvComponentPrefixes     = "COMPONENT_PREFIXES"
	EnvNamespaceLabelTags    = "NAMESPACE_LABEL_TAGS"
	EnvWorkloadLabelTags     = "WORKLOAD_LABEL_TAGS"
	EnvResyncPeriod          = "RESYNC_PERIOD"
	EnvConcurrency           = "CONCURRENCY"
	EnvReportKinds           = "REPORT_KINDS"
)

// Keys of the credentials Secret.
const (
	SecretKeyURL   = "url"
	SecretKeyToken = "token"
)

const (
	defaultProductType     = "KubeRocketCI"
	defaultComponentPrefix = "in-cluster-"
	defaultResyncPeriod    = 30 * time.Minute
	minResyncPeriod        = time.Minute
	defaultConcurrency     = 2
	listSeparator          = ","
	errInvalidConfig       = "invalid configuration"
)

// Config is the configuration of the Trivy module.
type Config struct {
	// OperatorNamespace is the namespace that holds the credentials Secret.
	OperatorNamespace string
	// SecretName is the credentials Secret with the keys "url" and "token".
	SecretName string
	// ProductType is the DefectDojo product type of the namespace products.
	ProductType string
	// ClusterName is the unique name of the cluster in DefectDojo. It has no default: the namespace products are
	// named "<ClusterName>/<namespace>", and the tests of this cluster carry the tag "k8s-cluster:<ClusterName>".
	ClusterName string
	// ExcludeNamespaces holds glob patterns of namespaces that are skipped.
	ExcludeNamespaces []string
	// ComponentPrefixes are stripped from the Argo CD application name to derive the component tag.
	ComponentPrefixes []string
	// NamespaceLabelTags lists the keys of the Namespace labels that become tags of the namespace product, as
	// "<label key>:<label value>". Empty copies none.
	NamespaceLabelTags []string
	// WorkloadLabelTags lists the keys of the workload labels that become tags of the tests of the workload, as
	// "<label key>:<label value>". Empty copies none.
	WorkloadLabelTags []string
	// ResyncPeriod is the interval of the periodic requeue of a namespace.
	ResyncPeriod time.Duration
	// Concurrency is the number of namespaces reconciled in parallel.
	Concurrency int
	// ReportKinds lists the Trivy report kinds that are imported, each once: LoadConfig drops a repeated kind.
	ReportKinds []string
}

// LoadConfigFromEnv reads the configuration from the process environment and validates it.
func LoadConfigFromEnv() (Config, error) {
	return LoadConfig(os.LookupEnv)
}

// LoadConfig reads the configuration through lookup, applies the defaults and validates the result.
// A variable that is set but empty keeps the list variables empty and takes the default for the others.
func LoadConfig(lookup func(string) (string, bool)) (Config, error) {
	env := &envReader{lookup: lookup}

	cfg := Config{
		OperatorNamespace:  env.get(EnvPodNamespace, ""),
		SecretName:         env.get(EnvDefectDojoSecretName, ""),
		ProductType:        env.get(EnvDefectDojoProductType, defaultProductType),
		ClusterName:        env.get(EnvClusterName, ""),
		ExcludeNamespaces:  env.list(EnvExcludeNamespaces, nil),
		ComponentPrefixes:  env.list(EnvComponentPrefixes, []string{defaultComponentPrefix}),
		NamespaceLabelTags: env.list(EnvNamespaceLabelTags, nil),
		WorkloadLabelTags:  env.list(EnvWorkloadLabelTags, nil),
		ReportKinds:        uniqueInOrder(env.list(EnvReportKinds, slices.Clone(trivy.ReportKinds))),
		ResyncPeriod:       parseEnv(env, EnvResyncPeriod, defaultResyncPeriod, time.ParseDuration),
		Concurrency:        parseEnv(env, EnvConcurrency, defaultConcurrency, strconv.Atoi),
	}

	if len(env.errs) > 0 {
		return Config{}, invalidConfig(env.errs)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// envReader reads configuration variables through lookup and collects their parse errors.
type envReader struct {
	lookup func(string) (string, bool)
	errs   []error
}

// get returns the trimmed value of key, or def when the variable is unset or blank.
func (e *envReader) get(key, def string) string {
	if v, ok := e.lookup(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	return def
}

// list returns the items of the comma-separated variable key, or def when the variable is unset.
func (e *envReader) list(key string, def []string) []string {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}

	return splitList(v)
}

// parseEnv parses key with parse, or returns def when the variable is unset or blank. A parse error is recorded
// in e and def is returned.
func parseEnv[T any](e *envReader, key string, def T, parse func(string) (T, error)) T {
	raw := e.get(key, "")
	if raw == "" {
		return def
	}

	v, err := parse(raw)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))

		return def
	}

	return v
}

// Validate reports every violated constraint of the configuration.
func (c Config) Validate() error {
	errs := slices.Concat(c.identityErrors(), c.nameErrors(), c.tuningErrors(), c.reportKindErrors(), c.excludeErrors(),
		c.labelTagErrors())
	if len(errs) > 0 {
		return invalidConfig(errs)
	}

	return nil
}

// invalidConfig joins the violations of the configuration into one error.
func invalidConfig(errs []error) error {
	return fmt.Errorf("%s: %w", errInvalidConfig, errors.Join(errs...))
}

// identityErrors checks the operator namespace, the credentials Secret and the cluster name.
func (c Config) identityErrors() []error {
	var errs []error

	if c.OperatorNamespace == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvPodNamespace))
	}

	if c.SecretName == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvDefectDojoSecretName))
	}

	switch msgs := validation.IsDNS1123Label(c.ClusterName); {
	case c.ClusterName == "":
		errs = append(errs, fmt.Errorf("%s is required", EnvClusterName))
	case len(msgs) > 0:
		errs = append(errs, fmt.Errorf("%s must be a lowercase RFC 1123 DNS label, got %q: %s",
			EnvClusterName, c.ClusterName, strings.Join(msgs, "; ")))
	}

	return errs
}

// nameErrors checks the values that end up in DefectDojo, where a comma separates tags.
func (c Config) nameErrors() []error {
	var errs []error

	if c.ProductType == "" || strings.Contains(c.ProductType, listSeparator) {
		errs = append(errs, fmt.Errorf("%s must be non-empty and contain no comma, got %q",
			EnvDefectDojoProductType, c.ProductType))
	}

	for _, p := range c.ComponentPrefixes {
		if strings.Contains(p, listSeparator) {
			errs = append(errs, fmt.Errorf("%s: prefix %q must contain no comma", EnvComponentPrefixes, p))
		}
	}

	return errs
}

// tuningErrors checks the resync period and the concurrency.
func (c Config) tuningErrors() []error {
	var errs []error

	// A shorter period requeues every namespace almost at once, without the backoff of a failed pass.
	if c.ResyncPeriod < minResyncPeriod {
		errs = append(errs, fmt.Errorf("%s must be at least %s, got %s", EnvResyncPeriod, minResyncPeriod, c.ResyncPeriod))
	}

	if c.Concurrency < 1 {
		errs = append(errs, fmt.Errorf("%s must be at least 1, got %d", EnvConcurrency, c.Concurrency))
	}

	return errs
}

// reportKindErrors checks that at least one report kind is set and that every kind is supported.
func (c Config) reportKindErrors() []error {
	var errs []error

	if len(c.ReportKinds) == 0 {
		errs = append(errs, fmt.Errorf("%s must list at least one report kind", EnvReportKinds))
	}

	for _, k := range c.ReportKinds {
		if !slices.Contains(trivy.ReportKinds, k) {
			errs = append(errs, fmt.Errorf("%s: unsupported report kind %q", EnvReportKinds, k))
		}
	}

	return errs
}

// excludeErrors checks that every exclude pattern is a valid glob.
func (c Config) excludeErrors() []error {
	var errs []error

	for _, p := range c.ExcludeNamespaces {
		if _, err := path.Match(p, ""); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid glob %q: %w", EnvExcludeNamespaces, p, err))
		}
	}

	return errs
}

// labelTagErrors checks the label keys of both label tag settings.
func (c Config) labelTagErrors() []error {
	return slices.Concat(labelKeyErrors(EnvNamespaceLabelTags, c.NamespaceLabelTags),
		labelKeyErrors(EnvWorkloadLabelTags, c.WorkloadLabelTags))
}

// labelKeyErrors checks the label keys of the setting env: each is a Kubernetes label key whose tag key is not one the
// operator writes itself and whose tag fits a DefectDojo tag with any label value, and no two keys give the same tag
// key.
func labelKeyErrors(env string, keys []string) []error {
	var errs []error

	seen := make(map[string]string, len(keys))

	for _, key := range keys {
		if err := labelKeyError(key); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", env, err))

			continue
		}

		tagKey := trivy.LabelTagKey(key)

		if first, ok := seen[tagKey]; ok {
			errs = append(errs, fmt.Errorf("%s: label keys %q and %q give the same tag key %q", env, first, key, tagKey))
		}

		seen[tagKey] = key
	}

	return errs
}

// labelKeyError returns why the label key cannot be the key of a tag, or nil.
func labelKeyError(key string) error {
	if msgs := validation.IsQualifiedName(key); len(msgs) > 0 {
		return fmt.Errorf("%q is not a valid label key: %s", key, strings.Join(msgs, "; "))
	}

	if tagKey := trivy.LabelTagKey(key); slices.Contains(trivy.ReservedTagKeys, tagKey) {
		return fmt.Errorf("label key %q gives the tag key %q, which the operator writes itself", key, tagKey)
	}

	if len(key) > trivy.MaxLabelKeyLen {
		return fmt.Errorf("label key %q is too long: it has %d characters, at most %d fit a tag with any label value",
			key, len(key), trivy.MaxLabelKeyLen)
	}

	return nil
}

// uniqueInOrder returns the items without repeats, each at its first occurrence.
func uniqueInOrder(items []string) []string {
	var out []string

	for _, item := range items {
		if !slices.Contains(out, item) {
			out = append(out, item)
		}
	}

	return out
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
