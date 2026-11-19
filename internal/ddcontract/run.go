package ddcontract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

// Scenario is a sequence of steps that starts on a DefectDojo without the product type of the run.
type Scenario struct {
	Name  string
	Steps []Step
}

// Step is one call of a scenario. Do returns the outcome of the call; an error stops the scenario: the target
// failed in a way the scenario does not expect, such as a transport error.
type Step struct {
	Name string
	Do   func(ctx context.Context, r *Runner) (Result, error)
}

// Result is the outcome of one step, with ordinals for IDs. At most one field is set.
type Result struct {
	Error    *Error          `json:"error,omitempty"`
	Reimport *Reimported     `json:"reimport,omitempty"`
	Products []ListedProduct `json:"products,omitempty"`
	Tests    []ListedTest    `json:"tests,omitempty"`
	Close    *Closed         `json:"close,omitempty"`
}

// Error is a failed call: the HTTP status of a DefectDojo answer and the fields its body names, or the client error
// without an answer.
type Error struct {
	Status int `json:"status,omitempty"`
	// Fields are the top-level keys of a JSON body other than message and pro: the form fields DefectDojo rejected.
	Fields  []string `json:"fields,omitempty"`
	Message string   `json:"message,omitempty"`
}

// Reimported is the answer of a reimport.
type Reimported struct {
	Test       int `json:"test"`
	Engagement int `json:"engagement"`
	Product    int `json:"product"`
}

// ListedProduct is a product of a products list.
type ListedProduct struct {
	Ref  int      `json:"ref"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// ListedTest is a test of a tests list.
type ListedTest struct {
	Ref            int      `json:"ref"`
	Title          string   `json:"title"`
	ScanType       string   `json:"scan_type"`
	Tags           []string `json:"tags"`
	BuildID        string   `json:"build_id"`
	Version        string   `json:"version"`
	LastEngagement bool     `json:"last_engagement"`
	Product        string   `json:"product"`
	Engagement     string   `json:"engagement"`
}

// Closed is the outcome of a close of a test.
type Closed struct {
	Reimports int    `json:"reimports"`
	OneByOne  int    `json:"one_by_one"`
	Fallback  *Error `json:"fallback,omitempty"`
}

// Recording is the outcome of every step of a scenario.
type Recording struct {
	Scenario string       `json:"scenario"`
	Steps    []StepRecord `json:"steps"`
}

// StepRecord is the outcome of one step and the state after it. Exchanges holds the HTTP requests of the client
// and the answers when the target records them; comparisons ignore them.
type StepRecord struct {
	Name      string     `json:"name"`
	Result    Result     `json:"result"`
	State     State      `json:"state"`
	Exchanges []Exchange `json:"exchanges,omitempty"`
}

// Recorder is a target that records the HTTP exchanges of the client.
type Recorder interface {
	// TakeExchanges returns the exchanges since the last call.
	TakeExchanges() []Exchange
}

// Runner runs the steps of one scenario against a target and keeps what the steps refer to.
type Runner struct {
	// run names the run: it is the product type and the cluster name of the products.
	run    string
	target Target
	refs   refs
	// raw is the state after the last step, with the IDs of the target.
	raw State
}

// NewRunner returns a runner for one scenario. The product type named run must not exist.
func NewRunner(target Target, run string) *Runner {
	return &Runner{run: run, target: target, refs: refs{}}
}

// Run runs every step of the scenario and reads the state after each.
func (r *Runner) Run(ctx context.Context, s Scenario) (Recording, error) {
	rec := Recording{Scenario: s.Name, Steps: make([]StepRecord, 0, len(s.Steps))}

	for i, step := range s.Steps {
		res, err := step.Do(ctx, r)
		if err != nil {
			return rec, fmt.Errorf("scenario %s, step %d %q: %w", s.Name, i+1, step.Name, err)
		}

		var exchanges []Exchange
		if recorder, ok := r.target.(Recorder); ok {
			exchanges = recorder.TakeExchanges()
		}

		raw, err := r.target.Snapshot(ctx, r.run)
		if err != nil {
			return rec, fmt.Errorf("scenario %s, step %d %q: read the state: %w", s.Name, i+1, step.Name, err)
		}

		r.raw = raw
		r.refs.learn(raw)

		rec.Steps = append(rec.Steps, StepRecord{
			Name:      step.Name,
			Result:    r.normalizeResult(res),
			State:     r.refs.normalize(raw, r.run),
			Exchanges: exchanges,
		})
	}

	return rec, nil
}

// normalizeResult replaces the IDs of the target with ordinals and the run name with Canonical. A step returns
// IDs of the target; the snapshot after the step has learned them.
func (r *Runner) normalizeResult(res Result) Result {
	if res.Reimport != nil {
		res.Reimport = &Reimported{
			Test:       r.refs.of(kindTest, res.Reimport.Test),
			Engagement: r.refs.of(kindEngagement, res.Reimport.Engagement),
			Product:    r.refs.of(kindProduct, res.Reimport.Product),
		}
	}

	for i, p := range res.Products {
		res.Products[i] = ListedProduct{
			Ref: r.refs.of(kindProduct, p.Ref), Name: replaceRun(p.Name, r.run), Tags: tagList(p.Tags),
		}
	}

	for i, t := range res.Tests {
		t.Ref = r.refs.of(kindTest, t.Ref)
		t.Tags = tagList(t.Tags)
		t.Product = replaceRun(t.Product, r.run)
		res.Tests[i] = t
	}

	if res.Error != nil {
		res.Error.Message = replaceRun(res.Error.Message, r.run)
	}

	return res
}

// engagementName is the engagement of every scenario test, as the operator names it.
const engagementName = "trivy-operator"

// scanDate is the scan date of every reimport of a scenario.
var scanDate = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// product returns the product name of the namespace in the run.
func (r *Runner) product(namespace string) string {
	return r.run + "/" + namespace
}

// request returns a reimport of the report into the test of the namespace product, as the operator sends it.
func (r *Runner) request(namespace, title, service string, report []byte) defectdojo.ReimportRequest {
	return defectdojo.ReimportRequest{
		ProductType: r.run,
		Product:     r.product(namespace),
		Engagement:  engagementName,
		TestTitle:   title,
		Service:     service,
		ScanDate:    scanDate,
		Report:      report,
	}
}

func (r *Runner) Reimport(ctx context.Context, req defectdojo.ReimportRequest) (Result, error) {
	res, err := r.target.Reimport(ctx, req)
	if err != nil {
		return failed(err)
	}

	return Result{Reimport: &Reimported{Test: res.TestID, Engagement: res.EngagementID, Product: res.ProductID}}, nil
}

// ListProducts lists the products of the product type whose name contains name.
func (r *Runner) ListProducts(ctx context.Context, productType, name string) (Result, error) {
	return r.listProducts(r.target.ListProducts(ctx, productType, name))
}

// ListProductsByName lists the products of the run whose name equals name.
func (r *Runner) ListProductsByName(ctx context.Context, name string) (Result, error) {
	return r.listProducts(r.target.ListProductsByName(ctx, r.run, name))
}

func (r *Runner) listProducts(products []defectdojo.Product, err error) (Result, error) {
	if err != nil {
		return failed(err)
	}

	res := Result{Products: make([]ListedProduct, 0, len(products))}
	for _, p := range products {
		res.Products = append(res.Products, ListedProduct{Ref: p.ID, Name: p.Name, Tags: p.Tags})
	}

	return res, nil
}

// ListTests lists the tests of the engagement of the namespace product.
func (r *Runner) ListTests(ctx context.Context, namespace string) (Result, error) {
	tests, err := r.listTests(ctx, namespace)
	if err != nil {
		return failed(err)
	}

	res := Result{Tests: make([]ListedTest, 0, len(tests))}
	for _, t := range tests {
		res.Tests = append(res.Tests, ListedTest{
			Ref: t.ID, Title: t.Title, ScanType: t.ScanType, Tags: t.Tags, BuildID: t.BuildID, Version: t.Version,
			LastEngagement: t.LastEngagement, Product: t.Product, Engagement: t.Engagement,
		})
	}

	return res, nil
}

// CloseTest closes the test of the namespace product with the title, as the tests list returns it.
func (r *Runner) CloseTest(ctx context.Context, namespace, title string) (Result, error) {
	test, err := r.listedTest(ctx, namespace, title)
	if err != nil {
		return Result{}, err
	}

	res, err := r.target.CloseTest(ctx, test)
	if err != nil {
		return failed(err)
	}

	closed := &Closed{Reimports: res.Reimports, OneByOne: res.OneByOne}
	if res.Fallback != nil {
		closed.Fallback = errorOf(res.Fallback)
	}

	return Result{Close: closed}, nil
}

// SetBuildID sets the build_id of the test of the namespace product with the title.
func (r *Runner) SetBuildID(ctx context.Context, namespace, title, buildID string) (Result, error) {
	test, err := r.rawTest(namespace, title)
	if err != nil {
		return Result{}, err
	}

	if err = r.target.SetBuildID(ctx, test.Ref, buildID); err != nil {
		return failed(err)
	}

	return Result{}, nil
}

// SetProductTags replaces the tags of the namespace product.
func (r *Runner) SetProductTags(ctx context.Context, namespace string, tags []string) (Result, error) {
	id, err := r.productID(namespace)
	if err != nil {
		return Result{}, err
	}

	if err = r.target.SetProductTags(ctx, id, tags); err != nil {
		return failed(err)
	}

	return Result{}, nil
}

// Triage sets the triage state on the finding of the service with the vulnerability ID, the lowest ID first, in the
// test of the namespace product.
func (r *Runner) Triage(ctx context.Context, namespace, title, service, vulnID string, triage Triage) (Result, error) {
	test, err := r.rawTest(namespace, title)
	if err != nil {
		return Result{}, err
	}

	findings := slices.Clone(test.Findings)
	slices.SortFunc(findings, func(a, b FindingState) int { return a.Ref - b.Ref })

	prefix := FoldTitle(vulnID + " ")

	for _, f := range findings {
		if f.Service == service && strings.HasPrefix(FoldTitle(f.Title), prefix) {
			return Result{}, r.target.Triage(ctx, f.Ref, triage)
		}
	}

	return Result{}, fmt.Errorf("test %q has no finding %s of service %q", title, vulnID, service)
}

// EnableRiskAcceptance turns on the simple risk acceptance of the namespace product.
func (r *Runner) EnableRiskAcceptance(ctx context.Context, namespace string) (Result, error) {
	id, err := r.productID(namespace)
	if err != nil {
		return Result{}, err
	}

	return Result{}, r.target.EnableRiskAcceptance(ctx, id)
}

// AddEngagement creates another engagement of the scenario in the namespace product.
func (r *Runner) AddEngagement(ctx context.Context, namespace string) (Result, error) {
	id, err := r.productID(namespace)
	if err != nil {
		return Result{}, err
	}

	return Result{}, r.target.AddEngagement(ctx, id, engagementName)
}

func (r *Runner) listTests(ctx context.Context, namespace string) ([]defectdojo.Test, error) {
	products, err := r.target.ListProductsByName(ctx, r.run, r.product(namespace))
	if err != nil {
		return nil, err
	}

	if len(products) != 1 {
		return nil, fmt.Errorf("%d products named %q", len(products), r.product(namespace))
	}

	return r.target.ListTests(ctx, products[0], engagementName)
}

// listedTest returns the test with the title that the operator would close: the listed one with the highest ID.
func (r *Runner) listedTest(ctx context.Context, namespace, title string) (defectdojo.Test, error) {
	tests, err := r.listTests(ctx, namespace)
	if err != nil {
		return defectdojo.Test{}, err
	}

	return newestTitled(tests, title, func(t defectdojo.Test) (string, int) { return t.Title, t.ID },
		r.product(namespace))
}

// rawTest returns the test with the title in the namespace product after the last step; the highest ID when several
// have the title.
func (r *Runner) rawTest(namespace, title string) (TestState, error) {
	product, err := r.rawProduct(namespace)
	if err != nil {
		return TestState{}, err
	}

	var tests []TestState
	for _, e := range product.Engagements {
		tests = append(tests, e.Tests...)
	}

	return newestTitled(tests, title, func(t TestState) (string, int) { return t.Title, t.Ref }, product.Name)
}

// newestTitled returns the item with the title and the highest ID; key gives the title and ID of an item.
func newestTitled[T any](items []T, title string, key func(T) (string, int), product string) (T, error) {
	var (
		found T
		best  int
	)

	for _, item := range items {
		if t, id := key(item); t == title && id > best {
			found, best = item, id
		}
	}

	if best == 0 {
		return found, fmt.Errorf("no test %q in %q", title, product)
	}

	return found, nil
}

func (r *Runner) productID(namespace string) (int, error) {
	product, err := r.rawProduct(namespace)

	return product.Ref, err
}

// rawProduct returns the namespace product after the last step.
func (r *Runner) rawProduct(namespace string) (ProductState, error) {
	for _, p := range r.raw.Products {
		if p.Name == r.product(namespace) {
			return p, nil
		}
	}

	return ProductState{}, fmt.Errorf("no product %q", r.product(namespace))
}

// failed turns an error of a call into a result. An error without a DefectDojo answer or a known meaning stops
// the scenario.
func failed(err error) (Result, error) {
	if e, known := knownError(err); known {
		return Result{Error: e}, nil
	}

	return Result{}, err
}

// errorOf is the error as a result; the error text for one without a DefectDojo answer or a known meaning.
func errorOf(err error) *Error {
	e, _ := knownError(err)

	return e
}

func knownError(err error) (*Error, bool) {
	var apiErr *defectdojo.APIError

	switch {
	case errors.As(err, &apiErr):
		return &Error{Status: apiErr.StatusCode, Fields: bodyFields(apiErr.Body)}, true
	case errors.Is(err, defectdojo.ErrProductTypeNotFound):
		return &Error{Message: defectdojo.ErrProductTypeNotFound.Error()}, true
	default:
		return &Error{Message: err.Error()}, false
	}
}

// bodyFields returns the top-level keys of a JSON object body, without message and pro, in their order. The client
// truncates the body of an APIError; the keys before a cut are returned.
func bodyFields(body string) []string {
	dec := json.NewDecoder(strings.NewReader(body))

	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}

	var fields []string

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fields
		}

		if key, ok := tok.(string); ok && key != "message" && key != "pro" {
			fields = append(fields, key)
		}

		var value json.RawMessage
		if err = dec.Decode(&value); err != nil {
			return fields
		}
	}

	return fields
}
