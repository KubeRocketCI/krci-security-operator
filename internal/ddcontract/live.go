package ddcontract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
)

// Live is a DefectDojo instance reached over its API. The client calls go through the operator client and are
// recorded; the reads of the state, the triage and the cleanup are not.
type Live struct {
	*defectdojo.Client

	baseURL  string
	apiToken string
	http     *http.Client
	recorder *recordingTransport
}

// NewLive returns a target for one run on the instance at baseURL. Retries are off: a retried request would be
// recorded twice.
func NewLive(baseURL, apiToken, run string) *Live {
	baseURL = strings.TrimRight(baseURL, "/")
	recorder := &recordingTransport{base: http.DefaultTransport, run: run}
	client := defectdojo.New(defectdojo.WithHTTPClient(&http.Client{Transport: recorder}), defectdojo.WithRetry(0, 0))

	return &Live{
		Client:   client.WithCredentials(baseURL, apiToken),
		baseURL:  baseURL,
		apiToken: apiToken,
		http:     &http.Client{Timeout: 2 * time.Minute},
		recorder: recorder,
	}
}

// TakeExchanges returns the exchanges of the client since the last call.
func (l *Live) TakeExchanges() []Exchange {
	return l.recorder.take()
}

// ServerInfo reads the version from the API schema (info.version) and the deduplication system setting.
func (l *Live) ServerInfo(ctx context.Context) (Server, error) {
	var (
		s      Server
		schema struct {
			Info struct {
				Version string `json:"version"`
			} `json:"info"`
		}
	)

	if err := l.getJSON(ctx, "/api/v2/oa3/schema/", url.Values{"format": {"json"}}, &schema); err != nil {
		return s, err
	}

	if schema.Info.Version == "" {
		return s, errors.New("the API schema has no info.version")
	}

	s.Version = schema.Info.Version

	var settings struct {
		Results []struct {
			Deduplication bool `json:"enable_deduplication"`
		} `json:"results"`
	}

	if err := l.getJSON(ctx, "/api/v2/system_settings/", nil, &settings); err != nil {
		return s, err
	}

	if len(settings.Results) != 1 {
		return s, fmt.Errorf("%d system settings", len(settings.Results))
	}

	s.Deduplication = settings.Results[0].Deduplication

	return s, nil
}

// Triage sets the triage state and makes the finding inactive, as the finding edit of the UI does.
func (l *Live) Triage(ctx context.Context, findingID int, triage Triage) error {
	return l.callJSON(ctx, http.MethodPatch, fmt.Sprintf("/api/v2/findings/%d/", findingID),
		map[string]any{string(triage): true, "active": false})
}

// EnableRiskAcceptance sets enable_simple_risk_acceptance of the product.
func (l *Live) EnableRiskAcceptance(ctx context.Context, productID int) error {
	return l.callJSON(ctx, http.MethodPatch, fmt.Sprintf("/api/v2/products/%d/", productID),
		map[string]any{"enable_simple_risk_acceptance": true})
}

// AddEngagement creates an engagement with the name in the product.
func (l *Live) AddEngagement(ctx context.Context, productID int, name string) error {
	day := scanDate.Format(time.DateOnly)

	return l.callJSON(ctx, http.MethodPost, "/api/v2/engagements/",
		map[string]any{"product": productID, "name": name, "target_start": day, "target_end": day})
}

// DeleteProductType deletes the product type with its products, engagements, tests and findings.
func (l *Live) DeleteProductType(ctx context.Context, name string) error {
	id, found, err := l.productTypeID(ctx, name)
	if err != nil || !found {
		return err
	}

	_, err = l.call(ctx, http.MethodDelete, fmt.Sprintf("/api/v2/product_types/%d/", id), nil)

	return err
}

func (l *Live) productTypeID(ctx context.Context, name string) (id int, found bool, err error) {
	err = getAll(ctx, l, "/api/v2/product_types/", url.Values{"name": {name}}, func(t named) {
		if t.Name == name {
			id, found = t.ID, true
		}
	})

	return id, found, err
}

// Snapshot reads the products of the product type with their engagements, tests, findings and import history.
func (l *Live) Snapshot(ctx context.Context, productType string) (State, error) {
	var s State

	typeID, found, err := l.productTypeID(ctx, productType)
	if err != nil || !found {
		return s, err
	}

	err = getAll(ctx, l, "/api/v2/products/", url.Values{"prod_type": {strconv.Itoa(typeID)}}, func(p defectdojo.Product) {
		s.Products = append(s.Products, ProductState{Ref: p.ID, Name: p.Name, Tags: p.Tags})
	})
	if err != nil {
		return s, err
	}

	for i := range s.Products {
		if s.Products[i].Engagements, err = l.engagements(ctx, s.Products[i].Ref); err != nil {
			return s, err
		}
	}

	return s, nil
}

func (l *Live) engagements(ctx context.Context, productID int) ([]EngagementState, error) {
	var out []EngagementState

	err := getAll(ctx, l, "/api/v2/engagements/", url.Values{"product": {strconv.Itoa(productID)}}, func(e named) {
		out = append(out, EngagementState{Ref: e.ID, Name: e.Name})
	})
	if err != nil {
		return nil, err
	}

	for i := range out {
		if out[i].Tests, err = l.tests(ctx, out[i].Ref); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func (l *Live) tests(ctx context.Context, engagementID int) ([]TestState, error) {
	var out []TestState

	filter := url.Values{"engagement": {strconv.Itoa(engagementID)}}

	err := getAll(ctx, l, "/api/v2/tests/", filter, func(t defectdojo.Test) {
		out = append(out, TestState{
			Ref: t.ID, Title: t.Title, ScanType: t.ScanType, Version: t.Version, BuildID: t.BuildID, Tags: t.Tags,
		})
	})
	if err != nil {
		return nil, err
	}

	for i := range out {
		id := url.Values{"test": {strconv.Itoa(out[i].Ref)}}

		err = getAll(ctx, l, "/api/v2/findings/", id, func(f apiFinding) {
			out[i].Findings = append(out[i].Findings, f.state())
		})
		if err != nil {
			return nil, err
		}

		err = getAll(ctx, l, "/api/v2/test_imports/", id, func(t testImport) {
			out[i].Imports = append(out[i].Imports, t.state())
		})
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

// named is a product type or an engagement as the API returns it.
type named struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// apiFinding is a finding as the API returns it; a null string decodes as empty.
type apiFinding struct {
	ID            int    `json:"id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	Service       string `json:"service"`
	Hash          string `json:"hash_code"`
	Active        bool   `json:"active"`
	Verified      bool   `json:"verified"`
	Mitigated     bool   `json:"is_mitigated"`
	FalsePositive bool   `json:"false_p"`
	RiskAccepted  bool   `json:"risk_accepted"`
	OutOfScope    bool   `json:"out_of_scope"`
}

func (f apiFinding) state() FindingState {
	return FindingState{
		Ref: f.ID, Title: f.Title, Severity: f.Severity, Service: f.Service, Hash: f.Hash, Active: f.Active,
		Verified: f.Verified, Mitigated: f.Mitigated, FalsePositive: f.FalsePositive, RiskAccepted: f.RiskAccepted,
		OutOfScope: f.OutOfScope,
	}
}

// testImport is an entry of the import history as the API returns it.
type testImport struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Actions []struct {
		Finding int    `json:"finding"`
		Action  string `json:"action"`
	} `json:"test_import_finding_action_set"`
}

// Import history actions of DefectDojo (dojo/test/models.py).
const (
	actionCreated     = "N"
	actionClosed      = "C"
	actionReactivated = "R"
	actionUntouched   = "U"
)

func (t testImport) state() ImportState {
	s := ImportState{Ref: t.ID, Type: t.Type}

	for _, a := range t.Actions {
		switch a.Action {
		case actionCreated:
			s.Created = append(s.Created, a.Finding)
		case actionClosed:
			s.Closed = append(s.Closed, a.Finding)
		case actionReactivated:
			s.Reactivated = append(s.Reactivated, a.Finding)
		case actionUntouched:
			s.Untouched = append(s.Untouched, a.Finding)
		}
	}

	return s
}

// getAll reads every page of the list endpoint and calls each with every result.
func getAll[T any](ctx context.Context, l *Live, path string, filter url.Values, each func(T)) error {
	const limit = 250

	for offset := 0; ; {
		q := url.Values{}
		for k, v := range filter {
			q[k] = v
		}

		q.Set("limit", strconv.Itoa(limit))
		q.Set("offset", strconv.Itoa(offset))

		var page struct {
			Next    *string `json:"next"`
			Results []T     `json:"results"`
		}

		if err := l.getJSON(ctx, path, q, &page); err != nil {
			return err
		}

		for _, item := range page.Results {
			each(item)
		}

		if page.Next == nil || len(page.Results) == 0 {
			return nil
		}

		offset += len(page.Results)
	}
}

func (l *Live) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	body, err := l.call(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}

	return nil
}

func (l *Live) callJSON(ctx context.Context, method, path string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode %s %s: %w", method, path, err)
	}

	_, err = l.call(ctx, method, path, raw)

	return err
}

func (l *Live) call(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, l.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build %s %s: %w", method, path, err)
	}

	req.Header.Set("Authorization", "Token "+l.apiToken)

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := l.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", method, path, err)
	}

	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &defectdojo.APIError{StatusCode: resp.StatusCode, Body: string(raw)}
	}

	return raw, nil
}
