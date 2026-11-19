package ddcontract

import (
	"context"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

// Target is a DefectDojo the scenarios run against: the client calls of the operator, the changes a DefectDojo user
// makes, and a read of the state.
type Target interface {
	Reimport(ctx context.Context, r defectdojo.ReimportRequest) (defectdojo.ReimportResult, error)
	ListProducts(ctx context.Context, productType, name string) ([]defectdojo.Product, error)
	ListProductsByName(ctx context.Context, productType, name string) ([]defectdojo.Product, error)
	ListTests(ctx context.Context, product defectdojo.Product, engagement string) ([]defectdojo.Test, error)
	CloseTest(ctx context.Context, test defectdojo.Test) (defectdojo.CloseResult, error)
	SetBuildID(ctx context.Context, testID int, buildID string) error
	SetProductTags(ctx context.Context, productID int, tags []string) error

	// Triage sets a triage state on the finding and makes it inactive, as a DefectDojo user does.
	Triage(ctx context.Context, findingID int, triage Triage) error
	// EnableRiskAcceptance turns on the simple risk acceptance of the product, which a risk acceptance by API needs.
	EnableRiskAcceptance(ctx context.Context, productID int) error
	// AddEngagement creates another engagement with the name in the product.
	AddEngagement(ctx context.Context, productID int, name string) error
	// Snapshot returns the products of the product type with their engagements, tests, findings and import history.
	Snapshot(ctx context.Context, productType string) (State, error)
}

// Triage is a triage state a DefectDojo user sets on a finding.
type Triage string

// Triage states.
const (
	TriageFalsePositive Triage = "false_p"
	TriageOutOfScope    Triage = "out_of_scope"
	TriageRiskAccepted  Triage = "risk_accepted"
)
