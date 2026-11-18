package trivy

import (
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"strings"

	"golang.org/x/text/cases"
)

// hashPartsFunc builds the hash parts of a result entry; ok is false for an entry the parts cannot be built from.
type hashPartsFunc func(entry map[string]any) (parts []string, ok bool)

// entryHashParts returns, per report kind, the parts of the DefectDojo 3.5.200 hash input of the finding that the
// Trivy Operator parser builds from a result entry: title, severity, vulnerability ids and description. The label
// parts of the description and the service are equal for all entries of a payload and are left out. ok is false
// for an entry the parts cannot be built from.
var entryHashParts = map[string]hashPartsFunc{
	KindVulnerabilityReport: vulnerabilityHashParts,
	KindExposedSecretReport: secretHashParts,
}

// pyField returns a field of an entry as the parser formats it: the default when the field is absent, "None" and
// isNull when it is null. ok is false for a value that is not a string or null.
func pyField(entry map[string]any, name, def string) (text string, isNull, ok bool) {
	value, present := entry[name]
	if !present {
		return def, false, true
	}

	if value == nil {
		return "None", true, true
	}

	text, ok = value.(string)

	return text, false, ok
}

func vulnerabilityHashParts(entry map[string]any) ([]string, bool) {
	id, idIsNull, ok1 := pyField(entry, "vulnerabilityID", "0")
	resource, _, ok2 := pyField(entry, "resource", "None")
	installed, _, ok3 := pyField(entry, "installedVersion", "None")
	title, _, ok4 := pyField(entry, "title", "None")
	fixed, _, ok5 := pyField(entry, "fixedVersion", "None")
	severity, ok6 := entry["severity"].(string)

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return nil, false
	}

	// The parser sets the vulnerability ids to the id when it is not empty; DefectDojo drops a blank one.
	ids := ""
	if !idIsNull && strings.TrimSpace(id) != "" {
		ids = id
	}

	return []string{
		id + " " + resource + " " + installed,
		severity,
		ids,
		title + "\n**Fixed version:** " + fixed + "\n",
	}, true
}

func secretHashParts(entry map[string]any) ([]string, bool) {
	target, _, ok1 := pyField(entry, "target", "")
	title, _, ok2 := pyField(entry, "title", "None")
	category, _, ok3 := pyField(entry, "category", "None")
	match, _, ok4 := pyField(entry, "match", "")
	ruleID, _, ok5 := pyField(entry, "ruleID", "0")
	severity, ok6 := entry["severity"].(string)

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return nil, false
	}

	return []string{
		"Secret detected in " + target + " - " + title,
		severity,
		"",
		title + "\n**Category:** " + category + "\n**Match:** " + match + "\n",
		"\n**ruleID:** " + ruleID,
	}, true
}

// collapseEntries replaces the result list of the report block of out with the list without the entries that
// repeat an earlier one. out is left untouched when no entry is dropped or the block or the list is missing.
func collapseEntries(out map[string]any, kind string) {
	hashParts := entryHashParts[kind]
	if hashParts == nil {
		return
	}

	block, _ := out["report"].(map[string]any)
	field := resultFields[kind]

	entries, _ := block[field].([]any)
	if len(entries) < 2 {
		return
	}

	kept := dropRepeated(entries, hashParts)
	if len(kept) == len(entries) {
		return
	}

	block = maps.Clone(block)
	block[field] = kept
	out["report"] = block
}

// dropRepeated returns the entries without those whose hash input repeats an earlier entry; the slice of entries
// itself when none is dropped. An entry that is not an object, or has no hash parts, is kept.
func dropRepeated(entries []any, hashParts hashPartsFunc) []any {
	fold := cases.Fold()
	seen := make(map[[sha256.Size]byte]struct{}, len(entries))

	var kept []any

	for i, entry := range entries {
		key, ok := entryKey(entry, hashParts, fold)
		if ok {
			if _, repeated := seen[key]; repeated {
				if kept == nil {
					kept = append(make([]any, 0, len(entries)-1), entries[:i]...)
				}

				continue
			}

			seen[key] = struct{}{}
		}

		if kept != nil {
			kept = append(kept, entry)
		}
	}

	if kept == nil {
		return entries
	}

	return kept
}

// entryKey returns the SHA-256 of the case-folded hash parts of the entry, each prefixed with its length.
func entryKey(entry any, hashParts hashPartsFunc, fold cases.Caser) (key [sha256.Size]byte, ok bool) {
	object, ok := entry.(map[string]any)
	if !ok {
		return key, false
	}

	parts, ok := hashParts(object)
	if !ok {
		return key, false
	}

	h := sha256.New()

	for _, part := range parts {
		folded := fold.String(part)

		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(folded))))
		_, _ = h.Write([]byte(folded))
	}

	h.Sum(key[:0])

	return key, true
}
