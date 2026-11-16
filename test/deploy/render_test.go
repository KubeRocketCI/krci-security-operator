// Package deploy_test renders the Helm chart with `helm template` and checks what the chart guarantees:
// the manager gets the configuration the code expects, and its access stays read-only. Without the
// helm binary the tests skip.
package deploy_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/KubeRocketCI/krci-security-operator/internal/controller/trivy"
)

const (
	releaseName      = "krci-security-operator"
	releaseNamespace = "krci-security"
	chartDir         = "../../deploy-templates"
	serviceAccount   = "edp-krci-security-operator"
	secretName       = "defectdojo-credentials"
	probePort        = 8081
)

// envNames are the variables the manager reads.
var envNames = []string{
	trivy.EnvPodNamespace,
	trivy.EnvDefectDojoSecretName,
	trivy.EnvDefectDojoProductType,
	trivy.EnvDefectDojoPlatformProd,
	trivy.EnvClusterName,
	trivy.EnvScopeStage,
	trivy.EnvScopeTenant,
	trivy.EnvScopePlatform,
	trivy.EnvExcludeNamespaces,
	trivy.EnvComponentPrefixes,
	trivy.EnvResyncPeriod,
	trivy.EnvConcurrency,
	trivy.EnvReportKinds,
}

type rendered []*unstructured.Unstructured

func render(t *testing.T, values ...string) rendered {
	t.Helper()

	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed, skipping chart render tests")
	}

	args := append([]string{"template", releaseName, chartDir, "--namespace", releaseNamespace}, values...)

	out, err := exec.Command("helm", args...).CombinedOutput()
	require.NoErrorf(t, err, "helm template failed: %s", out)

	var objs rendered

	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(out)))

	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return objs
		}

		require.NoError(t, err)

		data, err := utilyaml.ToJSON(doc)
		require.NoError(t, err)

		var obj map[string]any

		require.NoError(t, utiljson.Unmarshal(data, &obj))

		if obj != nil {
			objs = append(objs, &unstructured.Unstructured{Object: obj})
		}
	}
}

func (r rendered) count(kind string) int {
	n := 0

	for _, o := range r {
		if o.GetKind() == kind {
			n++
		}
	}

	return n
}

func (r rendered) one(t *testing.T, kind string) *unstructured.Unstructured {
	t.Helper()

	require.Equalf(t, 1, r.count(kind), "the chart renders one %s", kind)

	i := slices.IndexFunc(r, func(o *unstructured.Unstructured) bool { return o.GetKind() == kind })

	return r[i]
}

func container(t *testing.T, objs rendered) map[string]any {
	t.Helper()

	containers, _, err := unstructured.NestedSlice(objs.one(t, "Deployment").Object,
		"spec", "template", "spec", "containers")
	require.NoError(t, err)
	require.Len(t, containers, 1)

	c, ok := containers[0].(map[string]any)
	require.True(t, ok)

	return c
}

func stringList(t *testing.T, obj map[string]any, path ...string) []string {
	t.Helper()

	list, _, err := unstructured.NestedStringSlice(obj, path...)
	require.NoError(t, err, path)

	return list
}

// env returns the variables of the manager container. POD_NAMESPACE comes from the downward API and
// resolves to the release namespace.
func env(t *testing.T, c map[string]any) map[string]string {
	t.Helper()

	list, _, err := unstructured.NestedSlice(c, "env")
	require.NoError(t, err)

	vars := make(map[string]string, len(list))

	for _, item := range list {
		e, ok := item.(map[string]any)
		require.True(t, ok)

		key, _ := e["name"].(string)
		require.NotContainsf(t, vars, key, "%s is set twice", key)

		if value, ok := e["value"].(string); ok {
			vars[key] = value

			continue
		}

		field, _, err := unstructured.NestedString(e, "valueFrom", "fieldRef", "fieldPath")
		require.NoError(t, err)
		require.Equalf(t, "metadata.namespace", field, "%s has neither a value nor the namespace field", key)

		vars[key] = releaseNamespace
	}

	return vars
}

func loadConfig(t *testing.T, vars map[string]string) trivy.Config {
	t.Helper()

	cfg, err := trivy.LoadConfig(func(key string) (string, bool) {
		v, ok := vars[key]

		return v, ok
	})
	require.NoError(t, err)

	return cfg
}

// ports maps the container port names to their numbers.
func ports(t *testing.T, c map[string]any) map[string]int64 {
	t.Helper()

	list, _, err := unstructured.NestedSlice(c, "ports")
	require.NoError(t, err)

	out := make(map[string]int64, len(list))

	for _, item := range list {
		p, ok := item.(map[string]any)
		require.True(t, ok)

		portName, _ := p["name"].(string)
		number, ok := p["containerPort"].(int64)
		require.Truef(t, ok, "container port %q", portName)

		out[portName] = number
	}

	return out
}

func rules(t *testing.T, role *unstructured.Unstructured) []map[string]any {
	t.Helper()

	list, _, err := unstructured.NestedSlice(role.Object, "rules")
	require.NoError(t, err)
	require.NotEmpty(t, list)

	out := make([]map[string]any, 0, len(list))

	for _, item := range list {
		rule, ok := item.(map[string]any)
		require.True(t, ok)

		out = append(out, rule)
	}

	return out
}

func TestDefaults(t *testing.T) {
	objs := render(t)
	deploy := objs.one(t, "Deployment")

	replicas, _, err := unstructured.NestedInt64(deploy.Object, "spec", "replicas")
	require.NoError(t, err)
	require.EqualValues(t, 1, replicas, "one manager per cluster")

	sa, _, err := unstructured.NestedString(deploy.Object, "spec", "template", "spec", "serviceAccountName")
	require.NoError(t, err)
	require.Equal(t, serviceAccount, sa)

	c := container(t, objs)
	require.Equal(t, []string{"--leader-elect", fmt.Sprintf("--health-probe-bind-address=:%d", probePort)},
		stringList(t, c, "args"), "metrics are off by default")
	require.Equal(t, map[string]int64{"health": probePort}, ports(t, c))

	for _, probe := range []string{"livenessProbe", "readinessProbe"} {
		port, _, err := unstructured.NestedInt64(c, probe, "httpGet", "port")
		require.NoError(t, err)
		require.EqualValues(t, probePort, port, probe)
	}

	vars := env(t, c)
	require.ElementsMatch(t, envNames, slices.Collect(maps.Keys(vars)),
		"the chart sets exactly the variables the manager reads")

	// Only the Secret name has no default in the code.
	require.Equal(t,
		loadConfig(t, map[string]string{trivy.EnvPodNamespace: releaseNamespace, trivy.EnvDefectDojoSecretName: secretName}),
		loadConfig(t, vars), "the chart defaults are the code defaults")

	limit, _, err := unstructured.NestedString(c, "resources", "limits", "memory")
	require.NoError(t, err)
	require.Equal(t, "512Mi", limit)

	request, _, err := unstructured.NestedString(c, "resources", "requests", "memory")
	require.NoError(t, err)
	require.Equal(t, "128Mi", request)

	pod, _, err := unstructured.NestedMap(deploy.Object, "spec", "template", "spec", "securityContext")
	require.NoError(t, err)
	require.Equal(t, true, pod["runAsNonRoot"])
	require.Equal(t, map[string]any{"type": "RuntimeDefault"}, pod["seccompProfile"])

	sc, _, err := unstructured.NestedMap(c, "securityContext")
	require.NoError(t, err)
	require.Equal(t, false, sc["allowPrivilegeEscalation"])
	require.Equal(t, true, sc["readOnlyRootFilesystem"])
	require.Equal(t, []string{"ALL"}, stringList(t, c, "securityContext", "capabilities", "drop"))

	for _, kind := range []string{
		"Service", "ServiceMonitor", "CustomResourceDefinition",
		"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration",
	} {
		require.Zerof(t, objs.count(kind), "the chart renders no %s", kind)
	}
}

func TestValuesReachTheManager(t *testing.T) {
	objs := render(t,
		"--set", "defectdojo.secretName=dd-creds",
		"--set", "defectdojo.productType=Platform",
		"--set", "defectdojo.platformProduct=infra",
		"--set", "clusterName=sandbox",
		"--set", "scopes.stage=false",
		"--set", "scopes.tenant=false",
		"--set", "excludeNamespaces={kube-*,gitlab}",
		"--set", "componentPrefixes={in-cluster-,prod-}",
		"--set", "reportKinds={VulnerabilityReport}",
		"--set", "resyncPeriod=10m",
		"--set", "concurrency=4",
	)

	require.Equal(t, trivy.Config{
		OperatorNamespace: releaseNamespace,
		SecretName:        "dd-creds",
		ProductType:       "Platform",
		PlatformProduct:   "infra",
		ClusterName:       "sandbox",
		Scopes:            trivy.Scopes{Platform: true},
		ExcludeNamespaces: []string{"kube-*", "gitlab"},
		ComponentPrefixes: []string{"in-cluster-", "prod-"},
		ResyncPeriod:      10 * time.Minute,
		Concurrency:       4,
		ReportKinds:       []string{"VulnerabilityReport"},
	}, loadConfig(t, env(t, container(t, objs))))

	var names []string

	for _, rule := range rules(t, objs.one(t, "Role")) {
		if slices.Contains(stringList(t, rule, "resources"), "secrets") {
			names = append(names, stringList(t, rule, "resourceNames")...)
		}
	}

	require.Equal(t, []string{"dd-creds"}, names, "the Role grants the Secret the manager reads, and only that one")
}

func TestRBACIsReadOnly(t *testing.T) {
	objs := render(t)

	clusterRole := objs.one(t, "ClusterRole")
	for _, rule := range rules(t, clusterRole) {
		require.Subsetf(t, []string{"get", "list", "watch"}, stringList(t, rule, "verbs"), "ClusterRole rule %v", rule)
		require.NotContains(t, stringList(t, rule, "resources"), "secrets")
		require.NotContains(t, stringList(t, rule, "resources"), "*")
		require.NotContains(t, stringList(t, rule, "apiGroups"), "*")
	}

	// In the release namespace: leader election, events and the one credentials Secret.
	role := objs.one(t, "Role")
	for _, rule := range rules(t, role) {
		resources := stringList(t, rule, "resources")
		require.Len(t, resources, 1, rule)

		switch resources[0] {
		case "leases":
			require.Equal(t, []string{"coordination.k8s.io"}, stringList(t, rule, "apiGroups"))
		case "events":
			require.Equal(t, []string{"create"}, stringList(t, rule, "verbs"))
		case "secrets":
			require.Equal(t, []string{"get"}, stringList(t, rule, "verbs"))
			require.Equal(t, []string{secretName}, stringList(t, rule, "resourceNames"))
		default:
			t.Fatalf("unexpected rule in the Role: %v", rule)
		}
	}

	for kind, target := range map[string]*unstructured.Unstructured{"ClusterRoleBinding": clusterRole, "RoleBinding": role} {
		binding := objs.one(t, kind)

		ref, _, err := unstructured.NestedString(binding.Object, "roleRef", "name")
		require.NoError(t, err)
		require.Equal(t, target.GetName(), ref, kind)

		subjects, _, err := unstructured.NestedSlice(binding.Object, "subjects")
		require.NoError(t, err)
		require.Equal(t, []any{map[string]any{
			"kind": "ServiceAccount", "name": serviceAccount, "namespace": releaseNamespace,
		}}, subjects, kind)
	}
}

func TestMetrics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		port   int64
	}{
		{name: "default port", values: []string{"--set", "metrics.enabled=true"}, port: 8080},
		{name: "custom port", values: []string{"--set", "metrics.enabled=true", "--set", "metrics.port=9090"}, port: 9090},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := render(t, tc.values...)
			c := container(t, objs)

			require.Contains(t, stringList(t, c, "args"), fmt.Sprintf("--metrics-bind-address=:%d", tc.port))
			require.Equal(t, map[string]int64{"health": probePort, "metrics": tc.port}, ports(t, c))
			require.Zero(t, objs.count("Service"), "the chart exposes the metrics through no Service")
		})
	}
}
