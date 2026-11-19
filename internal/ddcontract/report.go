package ddcontract

import (
	"encoding/json"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// Vuln is a vulnerability of the package libssl 3.0.0 in a report.
type Vuln struct {
	ID       string
	Severity string
	Fixed    string
}

// Secret is an exposed secret in a report.
type Secret struct {
	RuleID   string
	Severity string
	Target   string
	Title    string
}

// Workload names the container a report is about.
type Workload struct {
	Namespace string
	Kind      string
	Name      string
	Container string
}

// Service is the finding service the operator sends for the workload.
func (w Workload) Service() string {
	return w.Namespace + "/" + w.Kind + "/" + w.Name + "/" + w.Container
}

func (w Workload) labels() map[string]string {
	return map[string]string{
		trivy.LabelResourceNamespace: w.Namespace,
		trivy.LabelResourceKind:      w.Kind,
		trivy.LabelResourceName:      w.Name,
		trivy.LabelContainerName:     w.Container,
	}
}

// VulnerabilityReport is the report of the workload with the vulnerabilities, in their order.
func VulnerabilityReport(w Workload, vulns ...Vuln) []byte {
	items := make([]map[string]string, 0, len(vulns))
	for _, v := range vulns {
		items = append(items, map[string]string{
			"vulnerabilityID":  v.ID,
			"resource":         "libssl",
			"installedVersion": "3.0.0",
			"fixedVersion":     v.Fixed,
			"severity":         v.Severity,
			"title":            v.ID + " in libssl",
		})
	}

	return marshalReport(trivy.KindVulnerabilityReport, w, map[string]any{"vulnerabilities": items})
}

// ExposedSecretReport is the report of the workload with the secrets, in their order.
func ExposedSecretReport(w Workload, secrets ...Secret) []byte {
	items := make([]map[string]string, 0, len(secrets))
	for _, s := range secrets {
		items = append(items, map[string]string{
			"ruleID":   s.RuleID,
			"category": "AWS",
			"match":    "AWS_ACCESS_KEY_ID=****",
			"severity": s.Severity,
			"target":   s.Target,
			"title":    s.Title,
		})
	}

	return marshalReport(trivy.KindExposedSecretReport, w, map[string]any{"secrets": items})
}

func marshalReport(kind string, w Workload, report map[string]any) []byte {
	raw, err := json.Marshal(map[string]any{
		"kind":     kind,
		"metadata": map[string]any{"labels": w.labels()},
		"report":   report,
	})
	if err != nil {
		panic(err)
	}

	return raw
}
