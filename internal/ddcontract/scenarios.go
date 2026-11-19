package ddcontract

import (
	"context"
	"fmt"
	"strings"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

const (
	scenarioNamespace = "ns"
	deployment        = "Deployment"
	vulnTitle         = "VulnerabilityReport deployment/app/app"
	secretTitle       = "ExposedSecretReport deployment/app/app"
)

var (
	app = Workload{Namespace: scenarioNamespace, Kind: deployment, Name: "app", Container: "app"}

	vulnA = Vuln{ID: "CVE-2026-0001", Severity: "HIGH", Fixed: "3.0.1"}
	// vulnACritical has the ID of vulnA and another severity: another finding identity.
	vulnACritical = Vuln{ID: "CVE-2026-0001", Severity: "CRITICAL", Fixed: "3.0.1"}
	vulnB         = Vuln{ID: "CVE-2026-0002", Severity: "LOW", Fixed: "3.0.2"}
	vulnC         = Vuln{ID: "CVE-2026-0003", Severity: "MEDIUM", Fixed: "3.0.3"}
	vulnD         = Vuln{ID: "CVE-2026-0004", Severity: "LOW", Fixed: "3.0.4"}

	awsKey = Secret{RuleID: "aws-access-key-id", Severity: "CRITICAL", Target: "app/.env", Title: "AWS Access Key ID"}

	workloadTags = []string{"k8s-workload:deployment/app", "k8s-container:app"}
)

// withContainer is another container of the workload.
func (w Workload) withContainer(name string) Workload {
	w.Container = name

	return w
}

// option changes a reimport request of a step.
type option func(r *Runner, req *defectdojo.ReimportRequest)

func withVersion(v string) option {
	return func(_ *Runner, req *defectdojo.ReimportRequest) { req.Version = v }
}

func withBuildID(id string) option {
	return func(_ *Runner, req *defectdojo.ReimportRequest) { req.BuildID = id }
}

func withTags(tags ...string) option {
	return func(_ *Runner, req *defectdojo.ReimportRequest) { req.Tags = tags }
}

func withService(service string) option {
	return func(_ *Runner, req *defectdojo.ReimportRequest) { req.Service = service }
}

func withTitle(title string) option {
	return func(_ *Runner, req *defectdojo.ReimportRequest) { req.TestTitle = title }
}

func inNamespace(ns string) option {
	return func(r *Runner, req *defectdojo.ReimportRequest) { req.Product = r.product(ns) }
}

// withProductOfLength sets a product name of n characters without the run name, which differs in length per run.
func withProductOfLength(n int) option {
	return func(_ *Runner, req *defectdojo.ReimportRequest) { req.Product = strings.Repeat("p", n) }
}

// upload reimports the report into the vulnerability test of the app container, version 1.0, as the operator does.
func upload(name string, report []byte, opts ...option) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		req := r.request(scenarioNamespace, vulnTitle, app.Service(), report)
		req.Version = "1.0"

		for _, o := range opts {
			o(r, &req)
		}

		return r.Reimport(ctx, req)
	}}
}

func listTests(name string) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		return r.ListTests(ctx, scenarioNamespace)
	}}
}

func listProducts(name string) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		return r.ListProducts(ctx, r.run, r.product(""))
	}}
}

func closeTest(name, title string) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		return r.CloseTest(ctx, scenarioNamespace, title)
	}}
}

func triageStep(name, service, vulnID string, t Triage) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		return r.Triage(ctx, scenarioNamespace, vulnTitle, service, vulnID, t)
	}}
}

func setBuildID(name, buildID string) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		return r.SetBuildID(ctx, scenarioNamespace, vulnTitle, buildID)
	}}
}

func setProductTags(name string, tags ...string) Step {
	return Step{Name: name, Do: func(ctx context.Context, r *Runner) (Result, error) {
		return r.SetProductTags(ctx, scenarioNamespace, tags)
	}}
}

// otherService is a second service of the app container test.
var otherService = app.withContainer("other").Service()

// ScenarioNamed returns the scenario with the name.
func ScenarioNamed(name string) (Scenario, bool) {
	for _, s := range Scenarios() {
		if s.Name == name {
			return s, true
		}
	}

	return Scenario{}, false
}

// Scenarios returns every contract scenario, in a fixed order. A changed scenario needs new fixtures.
func Scenarios() []Scenario {
	return []Scenario{
		firstReimport(),
		repeatedEntries(),
		reimportMatching(),
		buildID(),
		failedFirstReimport(),
		closing(),
		closeOneByOne(),
		closeWithoutActive(),
		productTags(),
		formValidation(),
		otherTestSameService(),
		twoEngagements(),
		riskAcceptance(),
	}
}

func firstReimport() Scenario {
	return Scenario{Name: "first-reimport", Steps: []Step{
		upload("reimport A, B into a new test", VulnerabilityReport(app, vulnA, vulnB), withTags(workloadTags...)),
		{Name: "list the products by exact name", Do: func(ctx context.Context, r *Runner) (Result, error) {
			return r.ListProductsByName(ctx, r.product(scenarioNamespace))
		}},
		{Name: "list the products by exact name in upper case", Do: func(ctx context.Context, r *Runner) (Result, error) {
			return r.ListProductsByName(ctx, strings.ToUpper(r.product(scenarioNamespace)))
		}},
		listTests("list the tests"),
		upload("reimport A, B again", VulnerabilityReport(app, vulnA, vulnB), withTags(workloadTags...)),
		upload("reimport A into another namespace product", VulnerabilityReport(app, vulnA), inNamespace("ns2")),
		listProducts("list the products whose name contains the cluster name"),
		{Name: "list the products of a missing product type", Do: func(ctx context.Context, r *Runner) (Result, error) {
			return r.ListProducts(ctx, r.run+"-missing", r.product(""))
		}},
	}}
}

// repeatedEntries checks that the import that creates the test does not match entries.
func repeatedEntries() Scenario {
	repeated := VulnerabilityReport(app, vulnA, vulnA, vulnB)

	return Scenario{Name: "repeated-entries", Steps: []Step{
		upload("first reimport of A, A, B", repeated),
		upload("reimport A, A, B", repeated),
		upload("reimport A, A, B again", repeated),
		upload("reimport B", VulnerabilityReport(app, vulnB)),
		upload("reimport A, A, B after A was gone", repeated),
	}}
}

func reimportMatching() Scenario {
	return Scenario{Name: "reimport-matching", Steps: []Step{
		upload("first reimport of A", VulnerabilityReport(app, vulnA)),
		upload("reimport A, B, B", VulnerabilityReport(app, vulnA, vulnB, vulnB)),
		upload("reimport B", VulnerabilityReport(app, vulnB)),
		upload("reimport A, D, C", VulnerabilityReport(app, vulnA, vulnD, vulnC)),
		upload("reimport A with another severity", VulnerabilityReport(app, vulnACritical)),
		upload("reimport A under another service", VulnerabilityReport(app, vulnA), withService(otherService)),
		upload("reimport nothing under the first service", VulnerabilityReport(app)),
	}}
}

func buildID() Scenario {
	return Scenario{Name: "build-id", Steps: []Step{
		upload("first reimport of A with a build_id", VulnerabilityReport(app, vulnA), withBuildID("uid:1:aaaa")),
		listTests("list the tests"),
		upload("reimport A with another build_id in spaces", VulnerabilityReport(app, vulnA), withBuildID(" uid:2:bbbb ")),
		upload("reimport A without a build_id", VulnerabilityReport(app, vulnA)),
		upload("reimport A with a blank build_id", VulnerabilityReport(app, vulnA), withBuildID("  ")),
		upload("reimport B with a build_id of 150 characters", VulnerabilityReport(app, vulnB),
			withBuildID(strings.Repeat("é", 150))),
		upload("reimport A with version 2.0 and a build_id of 151 characters", VulnerabilityReport(app, vulnA),
			withVersion("2.0"), withBuildID(strings.Repeat("é", 151))),
		setBuildID("set the build_id", "uid:3:cccc"),
		listTests("list the tests after the build_id is set"),
		setBuildID("clear the build_id", ""),
	}}
}

// failedFirstReimport checks that DefectDojo saves a new test with its build_id before it reads the report.
func failedFirstReimport() Scenario {
	return Scenario{Name: "failed-first-reimport", Steps: []Step{
		upload("first reimport of invalid JSON with a build_id and tags", []byte(`{`), withBuildID("uid:1:aaaa"),
			withTags(workloadTags...)),
		upload("reimport A into the test the failure created", VulnerabilityReport(app, vulnA), withBuildID("uid:1:aaaa")),
		upload("reimport invalid JSON with another build_id", []byte(`{`), withBuildID("uid:2:bbbb")),
		upload("first reimport of an unknown severity", VulnerabilityReport(app, Vuln{ID: "CVE-1", Severity: "SEVERE"}),
			withTitle("VulnerabilityReport deployment/severity/app")),
		upload("first reimport with a build_id of 151 characters", VulnerabilityReport(app, vulnA),
			withTitle("VulnerabilityReport deployment/long/app"), withBuildID(strings.Repeat("é", 151))),
	}}
}

func closing() Scenario {
	return Scenario{Name: "close", Steps: []Step{
		upload("first reimport of A, B under another service", VulnerabilityReport(app, vulnA, vulnB),
			withService(otherService)),
		upload("reimport A, B with a build_id and tags", VulnerabilityReport(app, vulnA, vulnB),
			withBuildID("uid:1:aaaa"), withTags(workloadTags...)),
		triageStep("mark B of the other service a false positive", otherService, vulnB.ID, TriageFalsePositive),
		triageStep("mark A out of scope", app.Service(), vulnA.ID, TriageOutOfScope),
		closeTest("close the test", vulnTitle),
		upload("reimport A, B", VulnerabilityReport(app, vulnA, vulnB)),
	}}
}

func closeOneByOne() Scenario {
	steps := make([]Step, 0, 8)

	var last string

	for i := range 6 {
		last = app.withContainer(fmt.Sprintf("c%d", i)).Service()
		steps = append(steps, upload(fmt.Sprintf("reimport A, B under service %d", i), VulnerabilityReport(app, vulnA, vulnB),
			withService(last)))
	}

	steps = append(steps,
		triageStep("mark B of the last service a false positive", last, vulnB.ID, TriageFalsePositive),
		closeTest("close the test", vulnTitle),
	)

	return Scenario{Name: "close-one-by-one", Steps: steps}
}

func closeWithoutActive() Scenario {
	return Scenario{Name: "close-without-active", Steps: []Step{
		upload("first reimport of A, B with a build_id", VulnerabilityReport(app, vulnA, vulnB), withBuildID("uid:1:aaaa")),
		triageStep("mark A a false positive", app.Service(), vulnA.ID, TriageFalsePositive),
		triageStep("mark B out of scope", app.Service(), vulnB.ID, TriageOutOfScope),
		closeTest("close the test", vulnTitle),
	}}
}

func productTags() Scenario {
	return Scenario{Name: "product-tags", Steps: []Step{
		upload("first reimport of A", VulnerabilityReport(app, vulnA)),
		listProducts("list the products"),
		setProductTags("set the product tags", "owner:team", "k8s-cluster:x"),
		listProducts("list the products with tags"),
		setProductTags("replace the product tags", "k8s-cluster:y"),
		setProductTags("set a product tag in upper case", "Owner:Team"),
		listProducts("list the products after the replace"),
	}}
}

func formValidation() Scenario {
	return Scenario{Name: "form-validation", Steps: []Step{
		upload("first reimport of A with tags in upper case", VulnerabilityReport(app, vulnA),
			withTags("K8s-Workload:Deployment/App")),
		upload("reimport A with a version in spaces", VulnerabilityReport(app, vulnA), withVersion(" 2.0 ")),
		upload("reimport A with a blank version", VulnerabilityReport(app, vulnA), withVersion(" ")),
		upload("reimport A with a tag with a space", VulnerabilityReport(app, vulnA), withTags("a b:1")),
		upload("reimport A with a tag with a single quote", VulnerabilityReport(app, vulnA), withTags("a'b:1")),
		upload("reimport A with a tag with a comma", VulnerabilityReport(app, vulnA), withTags("a,b:1")),
		upload("reimport A with a tag with a double quote", VulnerabilityReport(app, vulnA), withTags(`c"d:1`)),
		upload("reimport A with a tag in double quotes", VulnerabilityReport(app, vulnA), withTags(`"e:1"`)),
		upload("reimport A with a tag of 256 characters", VulnerabilityReport(app, vulnA),
			withTags("k:"+strings.Repeat("é", 254))),
		upload("reimport A with a tag of 255 characters", VulnerabilityReport(app, vulnA),
			withTags("k:"+strings.Repeat("é", 253))),
		upload("reimport A with a service of 201 characters", VulnerabilityReport(app, vulnA),
			withService(strings.Repeat("é", 201))),
		upload("reimport nothing with a service of 201 characters", VulnerabilityReport(app),
			withService(strings.Repeat("é", 201)), withVersion("3.0")),
		upload("first reimport of A with a service of 201 characters", VulnerabilityReport(app, vulnA),
			withService(strings.Repeat("é", 201)), withTitle("VulnerabilityReport deployment/service/app")),
		upload("reimport A with a service of 200 characters", VulnerabilityReport(app, vulnA),
			withService(strings.Repeat("é", 200))),
		upload("reimport B with a version of 101 characters", VulnerabilityReport(app, vulnB),
			withVersion(strings.Repeat("é", 101))),
		upload("first reimport of A with a version of 101 characters", VulnerabilityReport(app, vulnA),
			withVersion(strings.Repeat("é", 101)), withTitle("VulnerabilityReport deployment/version/app")),
		upload("reimport A into a test title of 256 characters", VulnerabilityReport(app, vulnA),
			withTitle(strings.Repeat("t", 256))),
		upload("reimport A into a product name of 256 characters", VulnerabilityReport(app, vulnA),
			withProductOfLength(256)),
		upload("reimport A without a version", VulnerabilityReport(app, vulnA), withVersion("")),
	}}
}

// otherTestSameService checks that the import that creates a test closes nothing in the other tests of the
// engagement: the tests of the two report kinds of a container have the same service.
func otherTestSameService() Scenario {
	return Scenario{Name: "other-test-same-service", Steps: []Step{
		upload("first reimport of A into the vulnerability test", VulnerabilityReport(app, vulnA)),
		upload("first reimport of an empty report into the secret test", ExposedSecretReport(app), withTitle(secretTitle)),
		upload("reimport a secret into the secret test", ExposedSecretReport(app, awsKey), withTitle(secretTitle)),
		closeTest("close the secret test", secretTitle),
	}}
}

func twoEngagements() Scenario {
	return Scenario{Name: "two-engagements", Steps: []Step{
		upload("first reimport of A", VulnerabilityReport(app, vulnA)),
		{Name: "add another engagement with the name", Do: func(ctx context.Context, r *Runner) (Result, error) {
			return r.AddEngagement(ctx, scenarioNamespace)
		}},
		upload("reimport A", VulnerabilityReport(app, vulnA)),
		listTests("list the tests"),
		closeTest("close the test of the last engagement", vulnTitle),
	}}
}

func riskAcceptance() Scenario {
	all := VulnerabilityReport(app, vulnA, vulnB, vulnC)

	return Scenario{Name: "risk-acceptance", Steps: []Step{
		upload("first reimport of A, B, C", all),
		{Name: "enable the simple risk acceptance of the product", Do: func(ctx context.Context, r *Runner) (Result, error) {
			return r.EnableRiskAcceptance(ctx, scenarioNamespace)
		}},
		triageStep("accept the risk of A", app.Service(), vulnA.ID, TriageRiskAccepted),
		upload("reimport A, B, C", all),
		upload("reimport B, C", VulnerabilityReport(app, vulnB, vulnC)),
		upload("reimport A, B, C after A was gone", all),
		triageStep("accept the risk of B", app.Service(), vulnB.ID, TriageRiskAccepted),
		closeTest("close the test", vulnTitle),
	}}
}
