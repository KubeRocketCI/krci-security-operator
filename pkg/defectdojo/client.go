// Package defectdojo is a minimal DefectDojo API v2 client for re-importing scan reports.
package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ScanTypeTrivyOperator is the DefectDojo parser for Trivy Operator reports.
	ScanTypeTrivyOperator = "Trivy Operator Scan"

	boolTrue = "true"

	reimportPath     = "/api/v2/reimport-scan/"
	productTypesPath = "/api/v2/product_types/"
	productsPath     = "/api/v2/products/"
	engagementsPath  = "/api/v2/engagements/"
	testsPath        = "/api/v2/tests/"
	findingsPath     = "/api/v2/findings/"

	defaultRequestTimeout = 2 * time.Minute
	// reimportTimeout bounds a re-import, which DefectDojo processes before it answers.
	reimportTimeout   = 10 * time.Minute
	defaultMaxRetries = 3
	defaultBackoff    = time.Second
	maxBackoff        = 30 * time.Second
	pageSize          = 100
)

// ErrTestNotNamed is returned for a test without product, engagement or title: only ListTests fills them.
var ErrTestNotNamed = errors.New("test has no product, engagement or title")

// ErrServiceRequired is returned by Reimport for a request without a service.
var ErrServiceRequired = errors.New("reimport has no service")

// ErrProductTypeNotFound is returned by ListProducts when the product type is not in the list of product types
// the token may read.
var ErrProductTypeNotFound = errors.New("product type not found")

// APIError is a non-2xx answer of DefectDojo.
type APIError struct {
	StatusCode int
	Body       string

	retryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("defectdojo answered %d: %s", e.StatusCode, e.Body)
}

// IsRejectedReport reports whether DefectDojo refused this one request (for example a malformed report)
// while the server itself is healthy, so the next request can still succeed.
func IsRejectedReport(err error) bool {
	var apiErr *APIError

	if !errors.As(err, &apiErr) {
		return false
	}

	switch apiErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}

	return apiErr.StatusCode >= http.StatusBadRequest && apiErr.StatusCode < http.StatusInternalServerError
}

// ReimportRequest describes one re-import of a report into a DefectDojo test.
type ReimportRequest struct {
	ProductType string
	Product     string
	Engagement  string
	TestTitle   string
	// Service replaces the service of every finding and limits the findings the reimport closes to that service.
	// Required. DefectDojo stores at most 200 characters; the caller shortens a longer value.
	Service  string
	Version  string
	Tags     []string
	ScanDate time.Time
	// Report is the JSON document handed to the Trivy Operator parser.
	Report []byte
}

// ReimportResult holds the identifiers DefectDojo answers with.
type ReimportResult struct {
	TestID       int `json:"test_id"`
	EngagementID int `json:"engagement_id"`
	ProductID    int `json:"product_id"`
}

// Product is a DefectDojo product as returned by the products list.
type Product struct {
	ID   int      `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// Test is a DefectDojo test of an engagement, as ListTests returns it.
type Test struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	// ScanType is the scan type DefectDojo reports for the test.
	ScanType string `json:"scan_type"`
	// Tags are the tags of the test. They are not used for ownership.
	Tags []string `json:"tags"`
	// Product and Engagement are the names of the product and the engagement the test was listed through.
	// Closing a test requires them with Title.
	Product    string `json:"-"`
	Engagement string `json:"-"`
}

// state is shared by every Client derived with WithCredentials.
type state struct {
	httpClient *http.Client
	maxRetries int
	backoff    time.Duration
	sleep      func(ctx context.Context, d time.Duration) error

	// Imports into one test run one at a time: concurrent re-imports duplicate findings.
	testLocks keyedMutex
	// DefectDojo creates the product type, product and engagement of a first import
	// non-atomically, so first imports of unknown contexts run one at a time.
	createMu sync.Mutex
	mu       sync.Mutex
	known    map[string]struct{}
	// productTypes holds the IDs of the product types found, by instance and name.
	productTypes map[string]int
}

// Client talks to one DefectDojo instance.
type Client struct {
	baseURL string
	token   string
	*state
}

// Option configures a Client.
type Option func(*state)

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(s *state) { s.httpClient = c }
}

// WithRetry sets the number of retries after the first attempt and the first backoff.
// The backoff doubles on every retry.
func WithRetry(maxRetries int, backoff time.Duration) Option {
	return func(s *state) {
		s.maxRetries = maxRetries
		s.backoff = backoff
	}
}

// New returns a Client without credentials; use WithCredentials to bind it to an instance.
func New(opts ...Option) *Client {
	s := &state{
		httpClient: &http.Client{},
		maxRetries: defaultMaxRetries,
		backoff:    defaultBackoff,
		sleep:      sleep,
		known:      map[string]struct{}{},

		productTypes: map[string]int{},
	}

	for _, o := range opts {
		o(s)
	}

	return &Client{state: s}
}

// WithCredentials returns a Client for the instance at baseURL that shares locks and state with c.
// Credentials are passed per call so a rotated Secret takes effect without a restart.
func (c *Client) WithCredentials(baseURL, token string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, state: c.state}
}

// Reimport re-imports the report into the test named by the request, creating the product type,
// product, engagement and test when they do not exist, and closes findings absent from the report.
func (c *Client) Reimport(ctx context.Context, r ReimportRequest) (ReimportResult, error) {
	if r.Service == "" {
		return ReimportResult{}, ErrServiceRequired
	}

	fields := make([][2]string, 0, 16+len(r.Tags))
	fields = append(fields, [][2]string{
		{"scan_type", ScanTypeTrivyOperator},
		{"product_type_name", r.ProductType},
		{"product_name", r.Product},
		{"engagement_name", r.Engagement},
		{"test_title", r.TestTitle},
		{"service", r.Service},
		{"version", r.Version},
		{"auto_create_context", boolTrue},
		{"close_old_findings", boolTrue},
		// Each engagement is its own deduplication scope.
		{"deduplication_on_engagement", boolTrue},
		{"active", boolTrue},
		{"verified", "false"},
		{"minimum_severity", "Info"},
		{"environment", "Development"},
		{"push_to_jira", "false"},
		{"scan_date", r.ScanDate.Format(time.DateOnly)},
	}...)

	for _, tag := range r.Tags {
		fields = append(fields, [2]string{"tags", tag})
	}

	// The key names the DefectDojo instance, so a changed base URL starts with every context unknown.
	contextKey := c.contextKey(r.Product, r.Engagement)

	unlock := c.testLocks.lock(testLockKey(contextKey, r.TestTitle))
	defer unlock()

	if !c.isKnown(contextKey) {
		c.createMu.Lock()
		defer c.createMu.Unlock()
	}

	res, err := c.postReport(ctx, fields, r.Report)
	if err != nil {
		return ReimportResult{}, err
	}

	c.markKnown(contextKey)

	return res, nil
}

// CloseTest mitigates every active finding of the test and keeps the test. A test without active findings
// is closed. It takes the lock of the re-import of the same test.
func (c *Client) CloseTest(ctx context.Context, test Test) error {
	// The lock is keyed by the names the re-import of the test uses; without them it would be a lock no
	// re-import shares.
	if test.Product == "" || test.Engagement == "" || test.Title == "" {
		return fmt.Errorf("%w: test %d", ErrTestNotNamed, test.ID)
	}

	unlock := c.testLocks.lock(testLockKey(c.contextKey(test.Product, test.Engagement), test.Title))
	defer unlock()

	// The list is read completely before anything is closed so closing does not shift the pages.
	ids, err := c.activeFindingIDs(ctx, test.ID)
	if err != nil {
		return err
	}

	for _, id := range ids {
		if err := c.closeFinding(ctx, id); err != nil {
			return err
		}
	}

	return nil
}

// testLockKey names one test by its context and title, the way a re-import finds it.
func testLockKey(contextKey, title string) string { return contextKey + "\x00" + title }

// findingRef holds the fields of a finding that closing needs.
type findingRef struct {
	ID int `json:"id"`
}

// activeFindingIDs returns the IDs of the findings of the test that are active and not mitigated.
func (c *Client) activeFindingIDs(ctx context.Context, testID int) ([]int, error) {
	var ids []int

	filter := url.Values{}
	filter.Set("test", strconv.Itoa(testID))
	filter.Set("active", boolTrue)
	filter.Set("is_mitigated", "false")

	err := listAll(ctx, c, findingsPath, "findings", filter, func(f findingRef) { ids = append(ids, f.ID) })
	if err != nil {
		return nil, err
	}

	return ids, nil
}

// listAll reads every page of the DefectDojo list endpoint with the filter and calls each with every result.
// The next offset is the number of results read, so a server that caps the page size is followed.
func listAll[T any](ctx context.Context, c *Client, endpoint, what string, filter url.Values, each func(T)) error {
	offset := 0

	for {
		q := make(url.Values, len(filter)+2)
		maps.Copy(q, filter)
		q.Set("limit", strconv.Itoa(pageSize))
		q.Set("offset", strconv.Itoa(offset))

		body, err := c.do(ctx, retryAll, defaultRequestTimeout, func(ctx context.Context) (*http.Request, error) {
			return c.newRequest(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil, "")
		})
		if err != nil {
			return err
		}

		var page struct {
			Next    *string `json:"next"`
			Results []T     `json:"results"`
		}

		if err = json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("failed to decode %s list: %w", what, err)
		}

		for _, item := range page.Results {
			each(item)
		}

		if page.Next == nil || len(page.Results) == 0 {
			return nil
		}

		// A server may answer with fewer results than the limit.
		offset += len(page.Results)
	}
}

func (c *Client) closeFinding(ctx context.Context, findingID int) error {
	payload, err := json.Marshal(map[string]any{
		"is_mitigated": true,
		"mitigated":    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to encode close request: %w", err)
	}

	// Mitigating a finding twice is harmless, so the close call is retried like a read.
	_, err = c.do(ctx, retryAll, defaultRequestTimeout, func(ctx context.Context) (*http.Request, error) {
		return c.newRequest(ctx, http.MethodPost, fmt.Sprintf("%s%d/close/", findingsPath, findingID),
			bytes.NewReader(payload), "application/json")
	})

	return err
}

// ListProducts returns the products of the product type whose name contains name, with their tags.
// DefectDojo has no name prefix filter: the caller checks the prefix. A product type that does not exist, or that
// the token cannot see, gives ErrProductTypeNotFound: DefectDojo answers the same way for both.
func (c *Client) ListProducts(ctx context.Context, productType, name string) ([]Product, error) {
	return c.listProducts(ctx, productType, "name", name)
}

// ListProductsByName returns the products of the product type whose name equals name, with their tags. DefectDojo
// compares case-insensitively: the caller compares the names. It reads one product, where ListProducts reads
// every product whose name contains name. ErrProductTypeNotFound as for ListProducts.
func (c *Client) ListProductsByName(ctx context.Context, productType, name string) ([]Product, error) {
	return c.listProducts(ctx, productType, "name_exact", name)
}

func (c *Client) listProducts(ctx context.Context, productType, nameFilter, name string) ([]Product, error) {
	typeID, found, err := c.productTypeID(ctx, productType)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("%w: %q", ErrProductTypeNotFound, productType)
	}

	var products []Product

	filter := url.Values{}
	filter.Set("prod_type", strconv.Itoa(typeID))
	filter.Set(nameFilter, name)

	err = listAll(ctx, c, productsPath, "products", filter, func(p Product) { products = append(products, p) })
	if err != nil {
		return nil, err
	}

	if len(products) == 0 {
		// The product type may have been deleted and created again under another ID.
		c.forgetProductType(productType)
	}

	return products, nil
}

func (c *Client) productTypeKey(name string) string { return c.baseURL + "\x00" + name }

func (c *Client) forgetProductType(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.productTypes, c.productTypeKey(name))
}

// productTypeID returns the ID of the product type with exactly this name. The ID is kept until a list of
// products under it comes back empty.
func (c *Client) productTypeID(ctx context.Context, name string) (id int, found bool, err error) {
	key := c.productTypeKey(name)

	c.mu.Lock()
	id, found = c.productTypes[key]
	c.mu.Unlock()

	if found {
		return id, true, nil
	}

	filter := url.Values{}
	filter.Set("name", name)

	type productType struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	err = listAll(ctx, c, productTypesPath, "product types", filter, func(t productType) {
		if t.Name == name {
			id, found = t.ID, true
		}
	})
	if err != nil || !found {
		return 0, false, err
	}

	c.mu.Lock()
	c.productTypes[key] = id
	c.mu.Unlock()

	return id, true, nil
}

// ListTests returns the tests of the engagement with exactly this name in the product, asking DefectDojo for
// the Trivy Operator Scan tests. Each test carries the scan type DefectDojo reports; the caller checks it.
// The engagement name filter is a contains match, so the name is checked here.
func (c *Client) ListTests(ctx context.Context, product Product, engagement string) ([]Test, error) {
	var engagementIDs []int

	filter := url.Values{}
	filter.Set("product", strconv.Itoa(product.ID))
	filter.Set("name", engagement)

	type engagementRef struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	err := listAll(ctx, c, engagementsPath, "engagements", filter, func(e engagementRef) {
		if e.Name == engagement {
			engagementIDs = append(engagementIDs, e.ID)
		}
	})
	if err != nil {
		return nil, err
	}

	var tests []Test

	for _, id := range engagementIDs {
		filter = url.Values{}
		filter.Set("engagement", strconv.Itoa(id))
		filter.Set("scan_type", ScanTypeTrivyOperator)

		err = listAll(ctx, c, testsPath, "tests", filter, func(t Test) {
			t.Product, t.Engagement = product.Name, engagement
			tests = append(tests, t)
		})
		if err != nil {
			return nil, err
		}
	}

	return tests, nil
}

// SetProductTags replaces the tags of the product with the list. DefectDojo replaces the tags on PATCH,
// so the list holds every tag the product keeps.
func (c *Client) SetProductTags(ctx context.Context, productID int, tags []string) error {
	payload, err := json.Marshal(map[string]any{"tags": tags})
	if err != nil {
		return fmt.Errorf("failed to encode product tags: %w", err)
	}

	// Setting the same list twice is harmless, so the call is retried like a read.
	_, err = c.do(ctx, retryAll, defaultRequestTimeout, func(ctx context.Context) (*http.Request, error) {
		return c.newRequest(ctx, http.MethodPatch, fmt.Sprintf("%s%d/", productsPath, productID),
			bytes.NewReader(payload), "application/json")
	})

	return err
}

func (c *Client) postReport(ctx context.Context, fields [][2]string, report []byte) (ReimportResult, error) {
	body, contentType, err := multipartBody(fields, report)
	if err != nil {
		return ReimportResult{}, err
	}

	// A re-import is not idempotent: a retry while DefectDojo still processes the first request would import
	// into the same test concurrently and duplicate findings.
	resp, err := c.do(ctx, retryThrottled, reimportTimeout, func(ctx context.Context) (*http.Request, error) {
		return c.newRequest(ctx, http.MethodPost, reimportPath, bytes.NewReader(body), contentType)
	})
	if err != nil {
		return ReimportResult{}, err
	}

	var res ReimportResult
	if err = json.Unmarshal(resp, &res); err != nil {
		return ReimportResult{}, fmt.Errorf("failed to decode re-import response: %w", err)
	}

	return res, nil
}

func (c *Client) newRequest(
	ctx context.Context,
	method, path string,
	body io.Reader,
	contentType string,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Authorization", "Token "+c.token)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req, nil
}

// retryPolicy tells which failures of a request are safe to retry.
type retryPolicy int

const (
	// retryAll retries 5xx, 429 and transport errors; for idempotent requests.
	retryAll retryPolicy = iota
	// retryThrottled retries only 429, the one answer that proves DefectDojo did not process the request.
	// A timeout, a transport error or a 5xx may leave the request running on the server.
	retryThrottled
)

func (p retryPolicy) retries(status int) bool {
	if p == retryThrottled {
		return status == http.StatusTooManyRequests
	}

	return retryable(status)
}

// do sends the request built by build with exponential backoff between the attempts the policy allows.
// Every attempt is bounded by timeout.
func (c *Client) do(
	ctx context.Context,
	policy retryPolicy,
	timeout time.Duration,
	build func(ctx context.Context) (*http.Request, error),
) ([]byte, error) {
	backoff := c.backoff

	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		body, retry, err := c.attempt(ctx, policy, timeout, build)
		if err == nil {
			return body, nil
		}

		lastErr = err

		if !retry {
			return nil, lastErr
		}

		var apiErr *APIError
		if errors.As(err, &apiErr) {
			backoff = max(backoff, apiErr.retryAfter)
		}

		if attempt == c.maxRetries {
			break
		}

		if err = c.sleep(ctx, min(backoff, maxBackoff)); err != nil {
			return nil, err
		}

		backoff *= 2
	}

	return nil, lastErr
}

// attempt sends the request once. retry tells whether the policy allows another attempt after the error.
func (c *Client) attempt(
	ctx context.Context,
	policy retryPolicy,
	timeout time.Duration,
	build func(ctx context.Context) (*http.Request, error),
) (body []byte, retry bool, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := build(reqCtx)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, fmt.Errorf("request to defectdojo aborted: %w", ctx.Err())
		}

		return nil, policy == retryAll, fmt.Errorf("request to defectdojo failed: %w", err)
	}

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	switch {
	case readErr != nil:
		return nil, policy == retryAll, fmt.Errorf("failed to read defectdojo response: %w", readErr)
	case resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices:
		return body, false, nil
	default:
		return nil, policy.retries(resp.StatusCode), &APIError{
			StatusCode: resp.StatusCode, Body: truncate(string(body)), retryAfter: retryAfter(resp),
		}
	}
}

func (c *Client) contextKey(product, engagement string) string {
	return c.baseURL + "\x00" + product + "\x00" + engagement
}

func (c *Client) isKnown(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.known[key]

	return ok
}

func (c *Client) markKnown(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.known[key] = struct{}{}
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func retryAfter(resp *http.Response) time.Duration {
	secs, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || secs < 0 {
		return 0
	}

	return time.Duration(secs) * time.Second
}

func truncate(s string) string {
	const limit = 300

	if len(s) > limit {
		return s[:limit]
	}

	return s
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for retry aborted: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

func multipartBody(fields [][2]string, report []byte) ([]byte, string, error) {
	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)

	for _, f := range fields {
		if err := w.WriteField(f[0], f[1]); err != nil {
			return nil, "", fmt.Errorf("failed to write field %s: %w", f[0], err)
		}
	}

	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="file"; filename="report.json"`)
	h.Set("Content-Type", "application/json")

	part, err := w.CreatePart(h)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create file part: %w", err)
	}

	if _, err = part.Write(report); err != nil {
		return nil, "", fmt.Errorf("failed to write file part: %w", err)
	}

	if err = w.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart body: %w", err)
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}

// keyedMutex serialises work per key.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()

	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}

	l, ok := k.locks[key]
	if !ok {
		l = &keyedLock{}
		k.locks[key] = l
	}

	l.refs++
	k.mu.Unlock()

	l.mu.Lock()

	return func() {
		l.mu.Unlock()
		k.mu.Lock()

		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}

		k.mu.Unlock()
	}
}
