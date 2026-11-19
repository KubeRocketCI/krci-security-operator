package ddcontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Exchange is one HTTP request of the client and the answer of DefectDojo. The Authorization header is not kept;
// the run name reads Canonical and every absolute URL points to http://defectdojo.
type Exchange struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// Form holds the multipart fields of a reimport, in their order; File the uploaded report.
	Form [][2]string     `json:"form,omitempty"`
	File json.RawMessage `json:"file,omitempty"`
	// Body is a JSON request body.
	Body     json.RawMessage `json:"body,omitempty"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

// recordingTransport records every exchange that passes through it.
type recordingTransport struct {
	base http.RoundTripper
	run  string

	mu        sync.Mutex
	exchanges []Exchange
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBody []byte

	if req.Body != nil {
		var err error

		reqBody, err = io.ReadAll(req.Body)
		_ = req.Body.Close()

		if err != nil {
			return nil, fmt.Errorf("read the request body: %w", err)
		}
	}

	out := req.Clone(req.Context())
	if reqBody != nil {
		out.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	resp, err := t.base.RoundTrip(out)
	if err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("read the response body: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	x := Exchange{Method: req.Method, Path: t.scrub(req.URL.RequestURI()), Status: resp.StatusCode}
	t.requestBody(&x, req.Header.Get("Content-Type"), reqBody)
	x.Response = t.document(respBody)

	t.mu.Lock()
	t.exchanges = append(t.exchanges, x)
	t.mu.Unlock()

	return resp, nil
}

func (t *recordingTransport) take() []Exchange {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := t.exchanges
	t.exchanges = nil

	return out
}

func (t *recordingTransport) requestBody(x *Exchange, contentType string, body []byte) {
	if len(body) == 0 {
		return
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" {
		x.Body = t.document(body)

		return
	}

	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])

	for {
		part, err := r.NextPart()
		if err != nil {
			return
		}

		value, err := io.ReadAll(part)
		if err != nil {
			return
		}

		if part.FileName() != "" {
			x.File = t.document(value)

			continue
		}

		x.Form = append(x.Form, [2]string{part.FormName(), t.scrub(string(value))})
	}
}

// maxTextLen bounds a body that is not JSON, such as an HTML error page.
const maxTextLen = 200

// document is the body as JSON: itself when it is JSON, else a string of at most maxTextLen bytes.
func (t *recordingTransport) document(body []byte) json.RawMessage {
	if len(body) == 0 {
		return nil
	}

	text := t.scrub(string(body))
	if json.Valid([]byte(text)) {
		return json.RawMessage(text)
	}

	if len(text) > maxTextLen {
		text = strings.ToValidUTF8(text[:maxTextLen], "")
	}

	raw, err := json.Marshal(text)
	if err != nil {
		return nil
	}

	return raw
}

var (
	absoluteURL = regexp.MustCompile(`https?://[A-Za-z0-9.\-:\[\]]+`)
	email       = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]+`)
)

// scrub replaces the run name, the host of absolute URLs and email addresses.
func (t *recordingTransport) scrub(s string) string {
	s = replaceRun(s, t.run)
	s = absoluteURL.ReplaceAllString(s, "http://defectdojo")

	return email.ReplaceAllString(s, "user@example.com")
}
