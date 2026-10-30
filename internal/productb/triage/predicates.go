package triage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// FactSet is the machine-readable input to predicate evaluation. Keys may be
// dotted paths; nested maps and structs are also traversed.
type FactSet map[string]any

// EvaluatePredicate evaluates a predicate conservatively. Missing facts,
// malformed operands, and unsupported operators are UNKNOWN.
func EvaluatePredicate(p Predicate, facts FactSet) ConditionStatus {
	switch p.Op {
	case "eq":
		l, lok := predicateValue(p.Left, facts)
		r, rok := predicateValue(p.Right, facts)
		if !lok || !rok {
			return ConditionUnknown
		}
		if reflect.DeepEqual(l, r) {
			return ConditionSatisfied
		}
		return ConditionUnsatisfied
	case "neq":
		l, lok := predicateValue(p.Left, facts)
		r, rok := predicateValue(p.Right, facts)
		if !lok || !rok {
			return ConditionUnknown
		}
		if !reflect.DeepEqual(l, r) {
			return ConditionSatisfied
		}
		return ConditionUnsatisfied
	case "in", "not_in":
		l, lok := predicateValue(p.Left, facts)
		r, rok := predicateValue(p.Right, facts)
		if !lok || !rok {
			return ConditionUnknown
		}
		rv := reflect.ValueOf(r)
		if rv.Kind() != reflect.Array && rv.Kind() != reflect.Slice {
			return ConditionUnknown
		}
		found := false
		for i := 0; i < rv.Len(); i++ {
			if reflect.DeepEqual(l, rv.Index(i).Interface()) {
				found = true
				break
			}
		}
		if p.Op == "not_in" {
			found = !found
		}
		if found {
			return ConditionSatisfied
		}
		return ConditionUnsatisfied
	case "exists", "missing":
		path := p.Path
		if path == "" {
			if s, ok := p.Left.(string); ok {
				path = s
			}
		}
		if path == "" {
			return ConditionUnknown
		}
		_, ok := lookupFact(facts, path)
		if p.Op == "missing" {
			ok = !ok
		}
		if ok {
			return ConditionSatisfied
		}
		return ConditionUnsatisfied
	case "changed":
		path := p.Path
		if path == "" {
			if s, ok := p.Left.(string); ok {
				path = s
			}
		}
		v, ok := lookupFact(facts, path)
		if !ok {
			return ConditionUnknown
		}
		if m, ok := v.(map[string]any); ok {
			if c, exists := m["changed"]; exists {
				if b, ok := c.(bool); ok {
					if b {
						return ConditionSatisfied
					}
					return ConditionUnsatisfied
				}
			}
			if _, ok := m["before"]; ok {
				if _, ok := m["after"]; ok {
					if !reflect.DeepEqual(m["before"], m["after"]) {
						return ConditionSatisfied
					}
					return ConditionUnsatisfied
				}
			}
		}
		return ConditionUnknown
	case "hash_matches":
		l, lok := predicateValue(p.Left, facts)
		r, rok := predicateValue(p.Right, facts)
		if !lok || !rok {
			return ConditionUnknown
		}
		ls, lok := l.(string)
		rs, rok := r.(string)
		if !lok || !rok {
			return ConditionUnknown
		}
		if ls == rs {
			return ConditionSatisfied
		}
		h := sha256.Sum256([]byte(ls))
		if hex.EncodeToString(h[:]) == rs {
			return ConditionSatisfied
		}
		return ConditionUnsatisfied
	case "all", "any":
		if len(p.Args) == 0 {
			return ConditionUnknown
		}
		unknown, satisfied := false, 0
		for _, a := range p.Args {
			s := EvaluatePredicate(a, facts)
			if s == ConditionUnknown {
				unknown = true
			}
			if s == ConditionSatisfied {
				satisfied++
			}
		}
		if p.Op == "all" {
			if satisfied == len(p.Args) {
				return ConditionSatisfied
			}
			if unknown {
				return ConditionUnknown
			}
			return ConditionUnsatisfied
		}
		if satisfied > 0 {
			return ConditionSatisfied
		}
		if unknown {
			return ConditionUnknown
		}
		return ConditionUnsatisfied
	case "not":
		if len(p.Args) != 1 {
			return ConditionUnknown
		}
		s := EvaluatePredicate(p.Args[0], facts)
		if s == ConditionSatisfied {
			return ConditionUnsatisfied
		}
		if s == ConditionUnsatisfied {
			return ConditionSatisfied
		}
		return ConditionUnknown
	default:
		return ConditionUnknown
	}
}

func predicateValue(v any, facts FactSet) (any, bool) {
	if m, ok := v.(map[string]any); ok {
		if f, exists := m["fact"]; exists {
			p, ok := f.(string)
			if !ok {
				return nil, false
			}
			return lookupFact(facts, p)
		}
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	if v == nil {
		return nil, false
	}
	return v, true
}

func lookupFact(facts FactSet, path string) (any, bool) {
	if v, ok := facts[path]; ok {
		return v, true
	}
	var cur any = map[string]any(facts)
	for _, part := range splitPath(path) {
		var ok bool
		cur, ok = mapPart(cur, part)
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
func splitPath(path string) []string {
	var out []string
	start := 0
	for i, r := range path {
		if r == '.' {
			out = append(out, path[start:i])
			start = i + 1
		}
	}
	return append(out, path[start:])
}
func mapPart(v any, key string) (any, bool) {
	if m, ok := v.(map[string]any); ok {
		x, exists := m[key]
		return x, exists
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, false
	}
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, false
	}
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Type().Field(i)
		name := f.Name
		if tag := f.Tag.Get("json"); tag != "" {
			for j, c := range tag {
				if c == ',' {
					name = tag[:j]
					break
				}
			}
			if name == "-" {
				continue
			}
		}
		if name == key {
			return rv.Field(i).Interface(), true
		}
	}
	return nil, false
}

// UnmarshalJSON retains Predicate's JSON-compatible shape while rejecting
// invalid JSON values through the standard decoder.
func (p *Predicate) UnmarshalJSON(data []byte) error {
	type plain Predicate
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var x plain
	if err := dec.Decode(&x); err != nil {
		return err
	}
	*p = Predicate(x)
	return nil
}
