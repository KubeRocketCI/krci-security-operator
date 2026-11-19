// Package ddcontract holds the DefectDojo contract scenarios: steps over the client calls of the operator, run
// against a live DefectDojo to record fixtures and against the fake DefectDojo of the controller tests to check it.
package ddcontract

import (
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/text/cases"
)

// State is what a target holds under the product type of a run after a step. A target returns it with its own IDs
// in the Ref fields; the runner replaces them with ordinals.
type State struct {
	Products []ProductState `json:"products"`
}

// ProductState is a product with its tags and engagements.
type ProductState struct {
	Ref         int               `json:"ref"`
	Name        string            `json:"name"`
	Tags        []string          `json:"tags"`
	Engagements []EngagementState `json:"engagements"`
}

// EngagementState is an engagement with its tests.
type EngagementState struct {
	Ref   int         `json:"ref"`
	Name  string      `json:"name"`
	Tests []TestState `json:"tests"`
}

// TestState is a test with the fields the operator reads, its findings and its import history.
type TestState struct {
	Ref      int            `json:"ref"`
	Title    string         `json:"title"`
	ScanType string         `json:"scan_type"`
	Version  string         `json:"version"`
	BuildID  string         `json:"build_id"`
	Tags     []string       `json:"tags"`
	Findings []FindingState `json:"findings"`
	Imports  []ImportState  `json:"imports"`
}

// FindingState is a finding. Title is case-folded: DefectDojo stores it title-cased, the hash code is computed from
// the folded value.
type FindingState struct {
	Ref           int    `json:"ref"`
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

// ImportState is one entry of the import history of a test: its type and the findings of each action.
type ImportState struct {
	Ref         int    `json:"ref"`
	Type        string `json:"type"`
	Created     []int  `json:"created"`
	Closed      []int  `json:"closed"`
	Reactivated []int  `json:"reactivated"`
	Untouched   []int  `json:"untouched"`
}

// Import history types of DefectDojo.
const (
	ImportTypeImport   = "import"
	ImportTypeReimport = "reimport"
)

// FoldTitle is the title as State holds it.
func FoldTitle(title string) string {
	return cases.Fold().String(title)
}

// refs maps the IDs of one target to ordinals per object kind, in the order the IDs are first seen; IDs first seen
// in the same state get ordinals in ascending ID order.
type refs map[string]map[int]int

func (r refs) assign(kind string, ids []int) {
	if r[kind] == nil {
		r[kind] = map[int]int{}
	}

	m := r[kind]

	for _, id := range slices.Sorted(slices.Values(ids)) {
		if _, ok := m[id]; !ok {
			m[id] = len(m) + 1
		}
	}
}

// of returns the ordinal of the ID; 0 when the ID was never seen.
func (r refs) of(kind string, id int) int {
	return r[kind][id]
}

const (
	kindProduct    = "product"
	kindEngagement = "engagement"
	kindTest       = "test"
	kindFinding    = "finding"
	kindImport     = "import"
)

// learn assigns ordinals to every ID of the state.
func (r refs) learn(s State) {
	ids := map[string][]int{}

	for _, p := range s.Products {
		ids[kindProduct] = append(ids[kindProduct], p.Ref)

		for _, e := range p.Engagements {
			ids[kindEngagement] = append(ids[kindEngagement], e.Ref)

			for _, t := range e.Tests {
				ids[kindTest] = append(ids[kindTest], t.Ref)

				for _, f := range t.Findings {
					ids[kindFinding] = append(ids[kindFinding], f.Ref)
				}

				for _, i := range t.Imports {
					ids[kindImport] = append(ids[kindImport], i.Ref)
				}
			}
		}
	}

	for kind, list := range ids {
		r.assign(kind, list)
	}
}

// normalize returns the state with ordinals for IDs, the run name replaced and every list in a fixed order.
func (r refs) normalize(s State, run string) State {
	out := State{Products: make([]ProductState, 0, len(s.Products))}

	for _, p := range s.Products {
		np := ProductState{
			Ref:         r.of(kindProduct, p.Ref),
			Name:        replaceRun(p.Name, run),
			Tags:        tagList(p.Tags),
			Engagements: make([]EngagementState, 0, len(p.Engagements)),
		}

		for _, e := range p.Engagements {
			np.Engagements = append(np.Engagements, r.normalizeEngagement(e))
		}

		slices.SortFunc(np.Engagements, func(a, b EngagementState) int { return a.Ref - b.Ref })
		out.Products = append(out.Products, np)
	}

	slices.SortFunc(out.Products, func(a, b ProductState) int { return a.Ref - b.Ref })

	return out
}

func (r refs) normalizeEngagement(e EngagementState) EngagementState {
	ne := EngagementState{Ref: r.of(kindEngagement, e.Ref), Name: e.Name, Tests: make([]TestState, 0, len(e.Tests))}

	for _, t := range e.Tests {
		ne.Tests = append(ne.Tests, r.normalizeTest(t))
	}

	slices.SortFunc(ne.Tests, func(a, b TestState) int { return a.Ref - b.Ref })

	return ne
}

func (r refs) normalizeTest(t TestState) TestState {
	nt := t
	nt.Ref = r.of(kindTest, t.Ref)
	nt.Tags = tagList(t.Tags)
	nt.Findings = make([]FindingState, 0, len(t.Findings))
	nt.Imports = make([]ImportState, 0, len(t.Imports))

	for _, f := range t.Findings {
		f.Ref = r.of(kindFinding, f.Ref)
		f.Title = FoldTitle(f.Title)
		nt.Findings = append(nt.Findings, f)
	}

	slices.SortFunc(nt.Findings, func(a, b FindingState) int { return a.Ref - b.Ref })

	for _, i := range t.Imports {
		nt.Imports = append(nt.Imports, ImportState{
			Ref:         r.of(kindImport, i.Ref),
			Type:        i.Type,
			Created:     r.findingRefs(i.Created),
			Closed:      r.findingRefs(i.Closed),
			Reactivated: r.findingRefs(i.Reactivated),
			Untouched:   r.findingRefs(i.Untouched),
		})
	}

	slices.SortFunc(nt.Imports, func(a, b ImportState) int { return a.Ref - b.Ref })

	return nt
}

func (r refs) findingRefs(ids []int) []int {
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.of(kindFinding, id))
	}

	slices.Sort(out)

	return out
}

// tagList returns a copy in the order of the target, never nil.
func tagList(tags []string) []string {
	return append([]string{}, tags...)
}

// Canonical is the run name of the fixtures: the product type and the cluster name of every scenario.
const Canonical = "ddcontract"

// runPatterns holds the compiled pattern of each run name.
var runPatterns sync.Map

// replaceRun replaces the run name, in any case, with Canonical; an upper-case run name with Canonical in upper case.
func replaceRun(s, run string) string {
	if run == "" || run == Canonical {
		return s
	}

	pattern, ok := runPatterns.Load(run)
	if !ok {
		pattern, _ = runPatterns.LoadOrStore(run, regexp.MustCompile("(?i)"+regexp.QuoteMeta(run)))
	}

	return pattern.(*regexp.Regexp).ReplaceAllStringFunc(s, func(match string) string {
		if match == strings.ToUpper(match) {
			return strings.ToUpper(Canonical)
		}

		return Canonical
	})
}
