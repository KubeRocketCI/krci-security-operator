package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/cases"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// Finding statuses as the DefectDojo UI shows them; see ddFinding.status.
const (
	statusActive        = "active"
	statusClosed        = "closed"
	statusFalsePositive = "false positive"
	statusRiskAccepted  = "risk accepted"
	statusOutOfScope    = "out of scope"
	statusInactive      = "inactive"
)

// maxBuildIDLen is the length of the build_id column of a test.
const maxBuildIDLen = 150

// firstTestID is the smallest ID the fake gives a new test. A new test gets an ID above every test seeded or
// created before; IDs are never reused.
const firstTestID = 100

// ddContext names the product type, product and engagement of a test.
type ddContext struct {
	productType string
	product     string
	engagement  string
}

// namespaceContext is the context of the Trivy tests of a namespace product of a cluster.
func namespaceContext(cluster, namespace string) ddContext {
	return ddContext{productType: "KubeRocketCI", product: cluster + "/" + namespace, engagement: "trivy-operator"}
}

type ddProduct struct {
	id          int
	name        string
	productType int
	tags        []string
}

type ddEngagement struct {
	id      int
	product int
	name    string
}

type ddTest struct {
	id         int
	engagement int
	scanType   string
	title      string
	version    string
	buildID    string
	tags       []string
}

// ddFinding is a stored finding. active and isMitigated are separate fields, as in DefectDojo: a false positive
// is inactive and not mitigated.
type ddFinding struct {
	id            int
	test          int
	title         string
	severity      string
	description   string
	service       string
	vulnIDs       []string
	hash          string
	active        bool
	verified      bool
	isMitigated   bool
	falsePositive bool
	riskAccepted  bool
	outOfScope    bool
}

// status gives the triage state first, then the mitigation.
func (f ddFinding) status() string {
	switch {
	case f.falsePositive:
		return statusFalsePositive
	case f.outOfScope:
		return statusOutOfScope
	case f.riskAccepted:
		return statusRiskAccepted
	case f.isMitigated:
		return statusClosed
	case f.active:
		return statusActive
	default:
		return statusInactive
	}
}

func (f *ddFinding) mitigate() {
	f.active = false
	f.isMitigated = true
}

// parsedFinding is a finding as the Trivy Operator parser gives it, before the reimport matches it.
type parsedFinding struct {
	title       string
	severity    string
	description string
	service     string
	vulnIDs     []string
}

// hash is the DefectDojo hash code of Trivy Operator Scan (Finding.hash_fields): the concatenation of title,
// severity, the sorted unique vulnerability ids, description and, when set, service (HASH_CODE_FIELDS_ALWAYS),
// case-folded and stripped of ASCII whitespace.
func (p parsedFinding) hash() string {
	ids := slices.Clone(p.vulnIDs)
	slices.Sort(ids)

	fields := p.title + p.severity + strings.Join(slices.Compact(ids), "") + p.description + p.service
	sum := sha256.Sum256([]byte(strings.Trim(cases.Fold().String(fields), " \t\n\r\v\f")))

	return hex.EncodeToString(sum[:])
}

// fakeDefectDojo models the DefectDojo 3.5.200 contract of the client calls the controller makes:
//   - reimport-scan as the client sends it: auto_create_context, close_old_findings, active=true, verified=false
//     and minimum_severity=Info are applied on every reimport, not read from the request;
//   - the test is the latest one of the engagement with the scan type and title, else a new one;
//   - a product of another product type is rejected;
//   - the reimport that creates the test creates one finding per report entry, without matching;
//   - on an existing test, findings match by hash code, the lowest ID first, and an entry that repeats a hash code
//     matches that same finding, so the other finding with the hash code is not matched; a hash code that is new
//     in the report gives one finding, however often it repeats; the request service replaces the parser service;
//   - the close set is the findings of the test with the request service, or without a service when none is sent;
//   - a matched closed finding is reactivated; false positive, risk accepted and out of scope are kept;
//     a finding of the close set missing from the report is closed and loses its risk acceptance;
//   - the version and the build_id are written, empty included, after the findings changed; a new test is saved with
//     its build_id before the report is read; the test tags are replaced when tags are sent;
//   - the lists are filtered as DefectDojo does: products by product type ID and name (contains, case-insensitive),
//     engagements by product and name, tests by engagement and scan type; PATCH of product tags replaces them;
//   - a form value of only whitespace or over its limit (service 200, version 100, test title and product name 255
//     characters) is rejected with 400; a build_id has no limit in the form and fails at the save of the test with 500
//     over 150 characters (the model limit), after the findings changed; a tag with a space, comma or quote or over
//     255 characters is rejected with 400 and stored in lower case; invalid JSON gives 400, an unknown severity 500;
//   - the lists return the build_id of each test and mark the tests of the last engagement with the name;
//     SetBuildID writes it; closing a test clears its build_id when the test has one as it was listed, as the client
//     does before it closes the findings.
//
// It also records the calls of the controller. The error hooks fail a call before it changes the state.
type fakeDefectDojo struct {
	mu sync.Mutex

	productTypes map[int]string
	products     map[int]*ddProduct
	engagements  map[int]*ddEngagement
	tests        map[int]*ddTest
	findings     map[int]*ddFinding
	// lastID holds the last ID per object kind.
	lastID map[string]int

	reimports []defectdojo.ReimportRequest
	closed    []int
	// tagCalls holds the product tag lists the controller sent.
	tagCalls  []tagCall
	listCalls int
	// testReads counts the ListTests calls.
	testReads int
	// buildIDUpdates counts the updates of the build_id of a test: SetBuildID and the clearing of a close.
	buildIDUpdates int

	reimportErr func(defectdojo.ReimportRequest) error
	// reimportAfterTestErr fails a reimport after DefectDojo resolved or created its test, before the findings change.
	reimportAfterTestErr func(defectdojo.ReimportRequest) error
	listErr              error
	tagErr               error
	buildIDErr           error
}

type tagCall struct {
	productID int
	tags      []string
}

func newFakeDefectDojo() *fakeDefectDojo {
	return &fakeDefectDojo{
		productTypes: map[int]string{},
		products:     map[int]*ddProduct{},
		engagements:  map[int]*ddEngagement{},
		tests:        map[int]*ddTest{},
		findings:     map[int]*ddFinding{},
		lastID:       map[string]int{"test": firstTestID - 1},
	}
}

func (f *fakeDefectDojo) Reimport(_ context.Context, r defectdojo.ReimportRequest) (defectdojo.ReimportResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reimports = append(f.reimports, r)

	if f.reimportErr != nil {
		if err := f.reimportErr(r); err != nil {
			return defectdojo.ReimportResult{}, err
		}
	}

	return f.reimport(r)
}

// reimport validates the form, resolves the test and then parses the report, in the order of DefectDojo. A first
// reimport creates the product type, product, engagement and test before the parser runs, and a parser failure
// keeps them: DefectDojo does not run a request in one transaction.
func (f *fakeDefectDojo) reimport(r defectdojo.ReimportRequest) (defectdojo.ReimportResult, error) {
	r, err := validateForm(r)
	if err != nil {
		return defectdojo.ReimportResult{}, err
	}

	test, created, err := f.targetTest(r)
	if err != nil {
		return defectdojo.ReimportResult{}, err
	}

	if f.reimportAfterTestErr != nil {
		if err = f.reimportAfterTestErr(r); err != nil {
			return defectdojo.ReimportResult{}, err
		}
	}

	parsed, err := parseTrivyOperatorReport(r.Report)
	if err != nil {
		return defectdojo.ReimportResult{}, err
	}

	if created {
		f.createFindings(test.id, r.Service, parsed)
	} else {
		f.applyFindings(test.id, r.Service, parsed)
	}

	if utf8.RuneCountInString(r.BuildID) > maxBuildIDLen {
		return defectdojo.ReimportResult{}, &defectdojo.APIError{
			StatusCode: http.StatusInternalServerError, Body: "Internal Server Error",
		}
	}

	test.version = r.Version
	test.buildID = r.BuildID

	if len(r.Tags) > 0 {
		test.tags = slices.Clone(r.Tags)
	}

	engagement := f.engagements[test.engagement]

	return defectdojo.ReimportResult{TestID: test.id, EngagementID: engagement.id, ProductID: engagement.product}, nil
}

// validateForm applies the DRF CharField rules to the string fields: an empty value is not sent, a value is
// stripped, a value of only whitespace is rejected, and a value over max_length characters is rejected.
func validateForm(r defectdojo.ReimportRequest) (defectdojo.ReimportRequest, error) {
	for name, field := range map[string]struct {
		value *string
		limit int
	}{
		"product_type_name": {&r.ProductType, 0},
		"product_name":      {&r.Product, 255},
		"engagement_name":   {&r.Engagement, 0},
		"test_title":        {&r.TestTitle, 255},
		"service":           {&r.Service, 200},
		"version":           {&r.Version, 100},
		"build_id":          {&r.BuildID, 0},
	} {
		if *field.value == "" {
			continue
		}

		if *field.value = strings.TrimSpace(*field.value); *field.value == "" {
			return r, badRequest(fmt.Sprintf(`{%q:["This field may not be blank."]}`, name))
		}

		if field.limit > 0 && utf8.RuneCountInString(*field.value) > field.limit {
			return r, badRequest(fmt.Sprintf(`{%q:["Ensure this field has no more than %d characters."]}`, name, field.limit))
		}
	}

	tags, err := validateTags(r.Tags)
	if err != nil {
		return r, err
	}

	r.Tags = tags

	return r, nil
}

// validateTags applies the TagListSerializerField rules: a tag has no space, comma, single quote or double quote
// (TAG_PATTERN), at most 255 characters (the tag name column), and is stored in lower case.
func validateTags(tags []string) ([]string, error) {
	stored := make([]string, 0, len(tags))

	for _, tag := range tags {
		if strings.ContainsAny(tag, ` ,'"`) {
			return nil, badRequest(fmt.Sprintf(`{"tags":["Invalid tag %q: it must not contain a space, a comma or a quote."]}`, tag))
		}

		if utf8.RuneCountInString(tag) > 255 {
			return nil, badRequest(`{"tags":["Ensure this tag has no more than 255 characters."]}`)
		}

		stored = append(stored, strings.ToLower(tag))
	}

	return stored, nil
}

// targetTest finds the test of the request, or creates it with its missing product type, product and engagement;
// created reports the latter. A new test is saved with the build_id of the request.
func (f *fakeDefectDojo) targetTest(r defectdojo.ReimportRequest) (test *ddTest, created bool, err error) {
	product := f.productNamed(r.Product)

	if product != nil && f.productTypes[product.productType] != r.ProductType {
		return nil, false, badRequest("The fetched product has a conflict with the supplied product type name: " +
			"supplied product type name - " + r.ProductType)
	}

	if product != nil {
		if engagement := f.lastEngagement(product.id, r.Engagement); engagement != nil {
			if test := f.latestTest(engagement.id, defectdojo.ScanTypeTrivyOperator, r.TestTitle); test != nil {
				return test, false, nil
			}
		}
	}

	if product == nil && r.ProductType == "" {
		return nil, false, badRequest("product_type_name parameter missing")
	}

	if utf8.RuneCountInString(r.BuildID) > maxBuildIDLen {
		return nil, false, &defectdojo.APIError{StatusCode: http.StatusInternalServerError, Body: "Internal Server Error"}
	}

	engagement := f.ensureContext(ddContext{productType: r.ProductType, product: r.Product, engagement: r.Engagement})

	test = f.addTest(engagement.id, f.nextID("test"), defectdojo.ScanTypeTrivyOperator, r.TestTitle, nil)
	test.buildID = r.BuildID

	return test, true, nil
}

// createFindings stores one finding per parsed entry, as the import into a new test does: no matching, so entries
// with an equal hash code give equal findings.
func (f *fakeDefectDojo) createFindings(testID int, service string, parsed []parsedFinding) {
	for _, p := range parsed {
		if service != "" {
			p.service = service
		}

		f.addFinding(testID, p)
	}
}

// applyFindings matches the parsed findings to the findings of the test and closes the rest of the close set.
func (f *fakeDefectDojo) applyFindings(testID int, service string, parsed []parsedFinding) {
	closeSet := map[int]struct{}{}
	byHash := map[string]*ddFinding{}

	for _, existing := range f.findingsOf(testID) {
		if existing.service == service {
			closeSet[existing.id] = struct{}{}
		}

		if _, ok := byHash[existing.hash]; !ok {
			byHash[existing.hash] = existing
		}
	}

	for _, p := range parsed {
		if service != "" {
			p.service = service
		}

		if existing, ok := byHash[p.hash()]; ok {
			matchFinding(existing)
			delete(closeSet, existing.id)

			continue
		}

		byHash[p.hash()] = f.addFinding(testID, p)
	}

	for id := range closeSet {
		if found := f.findings[id]; !found.isMitigated {
			found.mitigate()
			found.riskAccepted = false
		}
	}
}

// matchFinding updates a finding the report holds again: only a closed finding without a triage state changes.
func matchFinding(existing *ddFinding) {
	if existing.falsePositive || existing.outOfScope || existing.riskAccepted || !existing.isMitigated {
		return
	}

	existing.isMitigated = false
	existing.active = true
	existing.verified = false
}

// ListProducts returns, ordered by ID, the products of the product type whose name contains name.
// A product type that does not exist gives defectdojo.ErrProductTypeNotFound.
func (f *fakeDefectDojo) ListProducts(_ context.Context, productType, name string) ([]defectdojo.Product, error) {
	return f.listProducts(productType, func(have string) bool {
		return strings.Contains(strings.ToLower(have), strings.ToLower(name))
	})
}

// ListProductsByName returns, ordered by ID, the products of the product type whose name equals name, ignoring
// case, as the name_exact filter does.
func (f *fakeDefectDojo) ListProductsByName(_ context.Context, productType, name string) ([]defectdojo.Product, error) {
	return f.listProducts(productType, func(have string) bool { return strings.EqualFold(have, name) })
}

func (f *fakeDefectDojo) listProducts(productType string, matches func(name string) bool) ([]defectdojo.Product, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.listCalls++

	if f.listErr != nil {
		return nil, f.listErr
	}

	typeID := 0

	for id, have := range f.productTypes {
		if have == productType {
			typeID = id
		}
	}

	if typeID == 0 {
		return nil, fmt.Errorf("%w: %q", defectdojo.ErrProductTypeNotFound, productType)
	}

	var out []defectdojo.Product

	for _, id := range slices.Sorted(maps.Keys(f.products)) {
		p := f.products[id]
		if p.productType == typeID && matches(p.name) {
			out = append(out, defectdojo.Product{ID: p.id, Name: p.name, Tags: slices.Clone(p.tags)})
		}
	}

	return out, nil
}

// ListTests returns, ordered by ID, the Trivy Operator Scan tests of the engagements of the product that have
// exactly this name.
func (f *fakeDefectDojo) ListTests(_ context.Context, product defectdojo.Product, engagement string) ([]defectdojo.Test, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.listCalls++
	f.testReads++

	if f.listErr != nil {
		return nil, f.listErr
	}

	var out []defectdojo.Test

	last := f.lastEngagement(product.ID, engagement)

	for _, id := range slices.Sorted(maps.Keys(f.tests)) {
		test := f.tests[id]
		e := f.engagements[test.engagement]

		if e.product == product.ID && e.name == engagement && test.scanType == defectdojo.ScanTypeTrivyOperator {
			out = append(out, defectdojo.Test{
				ID: test.id, Title: test.title, ScanType: test.scanType, Tags: slices.Clone(test.tags),
				BuildID: test.buildID, LastEngagement: e == last, Product: product.Name, Engagement: engagement,
			})
		}
	}

	return out, nil
}

// CloseTest closes every active finding of the test, as the client does through the findings endpoints.
func (f *fakeDefectDojo) CloseTest(_ context.Context, test defectdojo.Test) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed = append(f.closed, test.ID)

	if test.BuildID != "" {
		f.buildIDUpdates++

		if stored, ok := f.tests[test.ID]; ok {
			stored.buildID = ""
		}
	}

	f.closeActive(test.ID)

	return nil
}

// SetBuildID sets the build_id of the test, as PATCH of the test does.
func (f *fakeDefectDojo) SetBuildID(_ context.Context, testID int, buildID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.buildIDUpdates++

	if f.buildIDErr != nil {
		return f.buildIDErr
	}

	test, ok := f.tests[testID]
	if !ok {
		return &defectdojo.APIError{StatusCode: http.StatusNotFound, Body: `{"detail":"Not found."}`}
	}

	test.buildID = buildID

	return nil
}

// SetProductTags replaces the tags of the product, as PATCH does.
func (f *fakeDefectDojo) SetProductTags(_ context.Context, productID int, tags []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.tagCalls = append(f.tagCalls, tagCall{productID: productID, tags: slices.Clone(tags)})

	if f.tagErr != nil {
		return f.tagErr
	}

	product, ok := f.products[productID]
	if !ok {
		return &defectdojo.APIError{StatusCode: http.StatusNotFound, Body: `{"detail":"Not found."}`}
	}

	product.tags = slices.Clone(tags)

	return nil
}

func (f *fakeDefectDojo) closeActive(testID int) {
	for _, found := range f.findingsOf(testID) {
		if found.active {
			found.mitigate()
		}
	}
}

// addEngagement creates another engagement with the name of the context, which becomes its last one, and the
// product and product type when they are missing.
func (f *fakeDefectDojo) addEngagement(c ddContext) {
	f.mu.Lock()
	defer f.mu.Unlock()

	product := f.ensureContext(c)
	engagement := &ddEngagement{id: f.nextID("engagement"), product: product.product, name: c.engagement}
	f.engagements[engagement.id] = engagement
}

// seedTests stores tests in the namespace product of the cluster under test and the namespace appNS, as written
// earlier by this operator.
func (f *fakeDefectDojo) seedTests(tests ...defectdojo.Test) {
	f.seedTestsIn(goAppContext, tests...)
}

// seedNamespace stores tests in the namespace product of a cluster and a namespace.
func (f *fakeDefectDojo) seedNamespace(cluster, namespace string, tests ...defectdojo.Test) {
	f.seedTestsIn(namespaceContext(cluster, namespace), tests...)
}

// seedProductTags sets the tags of the product as a user or an earlier version of the operator left them.
func (f *fakeDefectDojo) seedProductTags(product string, tags ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.productNamed(product).tags = slices.Clone(tags)
}

// productTags returns the tags of the product.
func (f *fakeDefectDojo) productTags(product string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.productNamed(product).tags)
}

// moveProduct puts the product under the product type, as a DefectDojo user does.
func (f *fakeDefectDojo) moveProduct(product, productType string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.productNamed(product).productType = f.ensureProductType(productType)
}

// hasProduct reports whether the product exists.
func (f *fakeDefectDojo) hasProduct(product string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.productNamed(product) != nil
}

// seedTestsIn stores Trivy Operator Scan tests in the context.
func (f *fakeDefectDojo) seedTestsIn(c ddContext, tests ...defectdojo.Test) {
	for _, test := range tests {
		f.seedScanTest(c, defectdojo.ScanTypeTrivyOperator, test)
	}
}

// seedScanTest stores a test of the scan type in the context. The ID must be free.
func (f *fakeDefectDojo) seedScanTest(c ddContext, scanType string, test defectdojo.Test) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, taken := f.tests[test.ID]; taken {
		panic(fmt.Sprintf("test %d is seeded twice", test.ID))
	}

	f.addTest(f.ensureContext(c).id, test.ID, scanType, test.Title, test.Tags).buildID = test.BuildID
	f.lastID["test"] = max(f.lastID["test"], test.ID)
}

// seedFinding stores an active finding in the test, as entered by hand or by another producer.
func (f *fakeDefectDojo) seedFinding(testID int, title, service string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.addFinding(testID, parsedFinding{title: title, severity: "Info", service: service})
}

// triage sets a triage state as a user does in DefectDojo: the finding becomes inactive.
func (f *fakeDefectDojo) triage(findingID int, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	found := f.findings[findingID]

	switch status {
	case statusFalsePositive:
		found.falsePositive = true
	case statusRiskAccepted:
		found.riskAccepted = true
	case statusOutOfScope:
		found.outOfScope = true
	default:
		panic("not a triage state: " + status)
	}

	found.active = false
}

func (f *fakeDefectDojo) deleteTest(testID int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, found := range f.findingsOf(testID) {
		delete(f.findings, found.id)
	}

	delete(f.tests, testID)
}

func (f *fakeDefectDojo) deleteAllTests() {
	for _, id := range f.testIDs() {
		f.deleteTest(id)
	}
}

// deleteProducts removes every product with its engagements, tests and findings.
func (f *fakeDefectDojo) deleteProducts() {
	f.deleteAllTests()

	f.mu.Lock()
	defer f.mu.Unlock()

	clear(f.engagements)
	clear(f.products)
}

func (f *fakeDefectDojo) testIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Sorted(maps.Keys(f.tests))
}

// test returns a copy of the test; the zero value when it does not exist.
func (f *fakeDefectDojo) test(testID int) ddTest {
	f.mu.Lock()
	defer f.mu.Unlock()

	test, ok := f.tests[testID]
	if !ok {
		return ddTest{}
	}

	out := *test
	out.tags = slices.Clone(test.tags)

	return out
}

// contextOf returns the product type, product and engagement of the test.
func (f *fakeDefectDojo) contextOf(testID int) ddContext {
	f.mu.Lock()
	defer f.mu.Unlock()

	engagement := f.engagements[f.tests[testID].engagement]
	product := f.products[engagement.product]

	return ddContext{productType: f.productTypes[product.productType], product: product.name, engagement: engagement.name}
}

func (f *fakeDefectDojo) counts() (productTypes, products, engagements int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.productTypes), len(f.products), len(f.engagements)
}

// findingsIn returns copies of the findings of the test, ordered by ID.
func (f *fakeDefectDojo) findingsIn(testID int) []ddFinding {
	f.mu.Lock()
	defer f.mu.Unlock()

	found := f.findingsOf(testID)
	out := make([]ddFinding, 0, len(found))

	for _, item := range found {
		out = append(out, *item)
	}

	return out
}

// statuses returns the status of every finding of the test with the service, by title.
func (f *fakeDefectDojo) statuses(testID int, service string) map[string]string {
	out := map[string]string{}

	for _, found := range f.findingsIn(testID) {
		if found.service == service {
			out[found.title] = found.status()
		}
	}

	return out
}

func (f *fakeDefectDojo) productNamed(name string) *ddProduct {
	for _, p := range f.products {
		if p.name == name {
			return p
		}
	}

	return nil
}

// ensureContext returns the last engagement of the context and creates what is missing.
func (f *fakeDefectDojo) ensureContext(c ddContext) *ddEngagement {
	product := f.productNamed(c.product)
	if product == nil {
		product = &ddProduct{id: f.nextID("product"), name: c.product, productType: f.ensureProductType(c.productType)}
		f.products[product.id] = product
	}

	if last := f.lastEngagement(product.id, c.engagement); last != nil {
		return last
	}

	engagement := &ddEngagement{id: f.nextID("engagement"), product: product.id, name: c.engagement}
	f.engagements[engagement.id] = engagement

	return engagement
}

// lastEngagement returns the engagement of the product with the name that was created last; DefectDojo
// engagement names are not unique.
func (f *fakeDefectDojo) lastEngagement(productID int, name string) *ddEngagement {
	var last *ddEngagement

	for _, id := range slices.Sorted(maps.Keys(f.engagements)) {
		if e := f.engagements[id]; e.product == productID && e.name == name {
			last = e
		}
	}

	return last
}

func (f *fakeDefectDojo) ensureProductType(name string) int {
	for id, have := range f.productTypes {
		if have == name {
			return id
		}
	}

	id := f.nextID("product type")
	f.productTypes[id] = name

	return id
}

// latestTest returns the test of the engagement with the scan type and title that was created last.
func (f *fakeDefectDojo) latestTest(engagementID int, scanType, title string) *ddTest {
	var latest *ddTest

	for _, id := range slices.Sorted(maps.Keys(f.tests)) {
		if t := f.tests[id]; t.engagement == engagementID && t.scanType == scanType && t.title == title {
			latest = t
		}
	}

	return latest
}

func (f *fakeDefectDojo) addTest(engagementID, id int, scanType, title string, tags []string) *ddTest {
	test := &ddTest{id: id, engagement: engagementID, scanType: scanType, title: title, tags: slices.Clone(tags)}
	f.tests[id] = test

	return test
}

func (f *fakeDefectDojo) addFinding(testID int, p parsedFinding) *ddFinding {
	found := &ddFinding{
		id:          f.nextID("finding"),
		test:        testID,
		title:       p.title,
		severity:    p.severity,
		description: p.description,
		service:     p.service,
		vulnIDs:     slices.Clone(p.vulnIDs),
		hash:        p.hash(),
		active:      true,
	}
	f.findings[found.id] = found

	return found
}

func (f *fakeDefectDojo) findingsOf(testID int) []*ddFinding {
	var out []*ddFinding

	for _, id := range slices.Sorted(maps.Keys(f.findings)) {
		if found := f.findings[id]; found.test == testID {
			out = append(out, found)
		}
	}

	return out
}

func (f *fakeDefectDojo) nextID(kind string) int {
	f.lastID[kind]++

	return f.lastID[kind]
}

func badRequest(body string) error {
	return &defectdojo.APIError{StatusCode: http.StatusBadRequest, Body: body}
}

// trivySeverities maps the Trivy severities to DefectDojo severities. Another value raises a KeyError in the
// parser, which DefectDojo answers with 500.
var trivySeverities = map[string]string{
	"CRITICAL": "Critical",
	"HIGH":     "High",
	"MEDIUM":   "Medium",
	"LOW":      "Low",
	"UNKNOWN":  "Info",
}

type trivyDocument struct {
	Metadata *struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Report *struct {
		Vulnerabilities []trivyVulnerability `json:"vulnerabilities"`
		Secrets         []trivySecret        `json:"secrets"`
	} `json:"report"`
}

// reportString is a string field of a report entry. The parser reads it with dict.get(name, default): an absent
// field is the default, a null field is None, which Python formats as "None".
type reportString struct {
	set  bool
	null bool
	text string
}

func (s *reportString) UnmarshalJSON(raw []byte) error {
	s.set = true

	if string(raw) == "null" {
		s.null = true

		return nil
	}

	return json.Unmarshal(raw, &s.text)
}

// or is the value the parser formats: def when the field is absent, "None" when it is null.
func (s reportString) or(def string) string {
	switch {
	case !s.set:
		return def
	case s.null:
		return "None"
	default:
		return s.text
	}
}

type trivyVulnerability struct {
	VulnerabilityID  reportString `json:"vulnerabilityID"`
	Resource         reportString `json:"resource"`
	InstalledVersion reportString `json:"installedVersion"`
	FixedVersion     reportString `json:"fixedVersion"`
	Severity         string       `json:"severity"`
	Title            reportString `json:"title"`
}

type trivySecret struct {
	RuleID   reportString `json:"ruleID"`
	Category reportString `json:"category"`
	Match    reportString `json:"match"`
	Severity string       `json:"severity"`
	Target   reportString `json:"target"`
	Title    reportString `json:"title"`
}

// severityOf maps a Trivy severity to the DefectDojo severity.
func severityOf(trivySeverity string) (string, error) {
	severity, ok := trivySeverities[trivySeverity]
	if !ok {
		return "", &defectdojo.APIError{StatusCode: http.StatusInternalServerError, Body: "Internal Server Error"}
	}

	return severity, nil
}

// parseTrivyOperatorReport gives the findings of a VulnerabilityReport or ExposedSecretReport as the DefectDojo
// Trivy Operator parser does (dojo/tools/trivy_operator). A report without metadata, labels or report block has
// no findings. The parser normalizes only KHV, KSV and KCV ids, which these report kinds do not hold.
func parseTrivyOperatorReport(raw []byte) ([]parsedFinding, error) {
	var doc trivyDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, badRequest("invalid report: " + err.Error())
	}

	if doc.Metadata == nil || doc.Metadata.Labels == nil || doc.Report == nil {
		return nil, nil
	}

	labels := doc.Metadata.Labels
	service := labels[trivy.LabelResourceNamespace] + "/" + labels[trivy.LabelResourceKind] + "/" +
		labels[trivy.LabelResourceName]

	if container := labels[trivy.LabelContainerName]; container != "" {
		service += "/" + container
	}

	resource := "\n**container.name:** " + labels[trivy.LabelContainerName] +
		"\n**resource.kind:** " + labels[trivy.LabelResourceKind] +
		"\n**resource.name:** " + labels[trivy.LabelResourceName] +
		"\n**resource.namespace:** " + labels[trivy.LabelResourceNamespace]

	out := make([]parsedFinding, 0, len(doc.Report.Vulnerabilities)+len(doc.Report.Secrets))

	for _, v := range doc.Report.Vulnerabilities {
		p, err := parseVulnerability(v, service, resource)
		if err != nil {
			return nil, err
		}

		out = append(out, p)
	}

	for _, s := range doc.Report.Secrets {
		p, err := parseSecret(s, service, resource)
		if err != nil {
			return nil, err
		}

		out = append(out, p)
	}

	return out, nil
}

func parseVulnerability(v trivyVulnerability, service, resource string) (parsedFinding, error) {
	severity, err := severityOf(v.Severity)
	if err != nil {
		return parsedFinding{}, err
	}

	id := v.VulnerabilityID.or("0")

	p := parsedFinding{
		title:    id + " " + v.Resource.or("None") + " " + v.InstalledVersion.or("None"),
		severity: severity,
		description: v.Title.or("None") + "\n**Fixed version:** " + v.FixedVersion.or("None") + "\n" +
			resource,
		service: service,
	}

	// A null id is falsy in the parser; DefectDojo drops a blank vulnerability id (sanitize_vulnerability_ids).
	if !v.VulnerabilityID.null && strings.TrimSpace(id) != "" {
		p.vulnIDs = []string{id}
	}

	return p, nil
}

func parseSecret(s trivySecret, service, resource string) (parsedFinding, error) {
	severity, err := severityOf(s.Severity)
	if err != nil {
		return parsedFinding{}, err
	}

	title := s.Title.or("None")

	return parsedFinding{
		title:    "Secret detected in " + s.Target.or("") + " - " + title,
		severity: severity,
		description: title + "\n**Category:** " + s.Category.or("None") + "\n**Match:** " +
			s.Match.or("") + "\n" + resource + "\n**ruleID:** " + s.RuleID.or("0"),
		service: service,
	}, nil
}
