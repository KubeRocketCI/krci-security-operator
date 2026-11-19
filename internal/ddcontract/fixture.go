package ddcontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
)

// Fixture is the recording of a scenario on a live DefectDojo.
type Fixture struct {
	DefectDojo Server `json:"defectdojo"`
	Recording
}

// Server is the DefectDojo a fixture was recorded on.
type Server struct {
	Version string `json:"version"`
	// Deduplication is the enable_deduplication system setting; with it, DefectDojo marks repeated findings as
	// duplicates after the import.
	Deduplication bool `json:"enable_deduplication"`
}

// nothing stands for a missing value in a difference.
const nothing = "nothing"

// ErrDeduplication is returned by Server.Check for a DefectDojo with deduplication on: the fake does not model it.
var ErrDeduplication = errors.New("DefectDojo has deduplication on")

// Check reports whether scenarios may be recorded on or verified against the server. Any version is accepted.
func (s Server) Check() error {
	if s.Deduplication {
		return fmt.Errorf("%w: turn enable_deduplication off in the system settings", ErrDeduplication)
	}

	return nil
}

// DefaultFixtureDir is the fixtures directory of this package in the source tree.
func DefaultFixtureDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "fixtures"
	}

	return filepath.Join(filepath.Dir(file), "fixtures")
}

func fixturePath(dir, scenario string) string {
	return filepath.Join(dir, scenario+".json")
}

// LoadFixture reads the fixture of the scenario from the directory.
func LoadFixture(dir, scenario string) (Fixture, error) {
	var f Fixture

	raw, err := os.ReadFile(fixturePath(dir, scenario))
	if err != nil {
		return f, fmt.Errorf("read the fixture of %s: %w", scenario, err)
	}

	if err = json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("decode the fixture of %s: %w", scenario, err)
	}

	return f, nil
}

// WriteFixture writes the fixture into the directory.
func WriteFixture(dir string, f Fixture) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the fixture of %s: %w", f.Scenario, err)
	}

	if err = os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	if err = os.WriteFile(fixturePath(dir, f.Scenario), append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write the fixture of %s: %w", f.Scenario, err)
	}

	return nil
}

// Compare returns the differences of the steps, results and states of two recordings of a scenario; none when they
// agree. Exchanges are not compared.
func Compare(recorded, actual Recording) []string {
	var diffs []string

	for i := range max(len(recorded.Steps), len(actual.Steps)) {
		switch {
		case i >= len(recorded.Steps):
			diffs = append(diffs, fmt.Sprintf("step %d %q: not recorded", i+1, actual.Steps[i].Name))

			continue
		case i >= len(actual.Steps):
			diffs = append(diffs, fmt.Sprintf("step %d %q: not run", i+1, recorded.Steps[i].Name))

			continue
		}

		want, got := recorded.Steps[i], actual.Steps[i]
		prefix := fmt.Sprintf("step %d %q: ", i+1, want.Name)

		if want.Name != got.Name {
			diffs = append(diffs, fmt.Sprintf("%sthe scenario runs %q", prefix, got.Name))

			continue
		}

		diffs = diffValues(diffs, prefix+"result", generic(want.Result), generic(got.Result))
		diffs = diffValues(diffs, prefix+"state", generic(want.State), generic(got.State))
	}

	return diffs
}

// generic is the value as encoding/json decodes it into any.
func generic(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	var out any
	if err = json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}

	return out
}

// diffValues appends a line for every path where the decoded JSON values differ.
func diffValues(diffs []string, path string, want, got any) []string {
	wantMap, wantIsMap := want.(map[string]any)
	gotMap, gotIsMap := got.(map[string]any)

	if wantIsMap && gotIsMap {
		return diffMaps(diffs, path, wantMap, gotMap)
	}

	wantList, wantIsList := want.([]any)
	gotList, gotIsList := got.([]any)

	if wantIsList && gotIsList && len(wantList) == len(gotList) {
		for i := range wantList {
			diffs = diffValues(diffs, fmt.Sprintf("%s[%d]", path, i), wantList[i], gotList[i])
		}

		return diffs
	}

	if reflect.DeepEqual(want, got) {
		return diffs
	}

	return append(diffs, fmt.Sprintf("%s: recorded %s, got %s", path, compact(want), compact(got)))
}

func diffMaps(diffs []string, path string, want, got map[string]any) []string {
	union := maps.Clone(want)
	maps.Copy(union, got)

	for _, k := range slices.Sorted(maps.Keys(union)) {
		diffs = diffValues(diffs, path+"."+k, want[k], got[k])
	}

	return diffs
}

func compact(v any) string {
	if v == nil {
		return nothing
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}

	return string(raw)
}
