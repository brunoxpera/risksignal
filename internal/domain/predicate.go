package domain

import (
	"encoding/json"
	"fmt"
	"strings"
)

// This file implements the bounded predicate language of the I4
// priority_rules model (ARCH-004 §1.1). A rule's definition is a small,
// total expression tree over the PriorityFactors, evaluated by the pure
// function EvaluateRule — deliberately not a general rule engine (ch. 9.3
// "konfigurierbar dokumentiert" means versioned data, not a scripting
// language).
//
// The vocabulary is closed:
//
//   - ops:    eq (bool/string), in (string set), ge (numeric threshold);
//   - fields: confidence, kev, cvss, epss, criticality, exposure — exactly
//     the PriorityFactors set (method is carried for traceability, never a
//     predicate input).
//
// Unknown fields, ops and values are errors, never silent defaults (the
// same rule as MatchMethod.Confidence returning ok=false): a typo cannot
// silently change a priority. A new factor is a new enum value, one
// evaluator branch and a migration.

// RuleOp is one atomic predicate operator of the bounded rule language.
type RuleOp string

// Allowed RuleOp values (ARCH-004 §1.1).
const (
	// RuleOpEq compares a bool (kev) or string (confidence, criticality,
	// exposure) field to a single value.
	RuleOpEq RuleOp = "eq"
	// RuleOpIn tests membership of a string field in a value set.
	RuleOpIn RuleOp = "in"
	// RuleOpGe is the numeric >= test for the cvss/epss thresholds.
	RuleOpGe RuleOp = "ge"
)

// Valid reports whether o is an allowed RuleOp value.
func (o RuleOp) Valid() bool {
	switch o {
	case RuleOpEq, RuleOpIn, RuleOpGe:
		return true
	}
	return false
}

// FactorField names one PriorityFactors field a predicate may read
// (ARCH-004 §1.1). Method is not part of the set: confidence is the
// derivable, authoritative predicate input.
type FactorField string

// Allowed FactorField values — exactly the ch. 9.3 predicate inputs.
const (
	FieldConfidence  FactorField = "confidence"
	FieldKEV         FactorField = "kev"
	FieldCVSS        FactorField = "cvss"
	FieldEPSS        FactorField = "epss"
	FieldCriticality FactorField = "criticality"
	FieldExposure    FactorField = "exposure"
)

// Valid reports whether f is an allowed FactorField value.
func (f FactorField) Valid() bool {
	switch f {
	case FieldConfidence,
		FieldKEV,
		FieldCVSS,
		FieldEPSS,
		FieldCriticality,
		FieldExposure:
		return true
	}
	return false
}

// RuleValueKind classifies the scalar carried by a RuleValue: the JSON
// predicate uses one polymorphic "value" key whose type is bool, string or
// number.
type RuleValueKind string

// Allowed RuleValueKind values.
const (
	RuleValueBool   RuleValueKind = "bool"
	RuleValueString RuleValueKind = "string"
	RuleValueNumber RuleValueKind = "number"
)

// RuleValue is the typed carrier of an atomic predicate's operand. It
// mirrors the JSON scalar of {"op":"eq","field":"kev","value":true} or
// {"op":"ge","field":"cvss","value":9.0} without resorting to
// encoding/json.RawMessage or a database type: the domain stays DB-agnostic
// and strongly typed (ARCH-004 §1.1).
type RuleValue struct {
	Kind RuleValueKind
	Bool bool
	Str  string
	Num  float64
}

// BoolValue returns a boolean rule value (the kev operand).
func BoolValue(b bool) *RuleValue { return &RuleValue{Kind: RuleValueBool, Bool: b} }

// StringValue returns a string rule value (a confidence/criticality/exposure
// operand).
func StringValue(s string) *RuleValue { return &RuleValue{Kind: RuleValueString, Str: s} }

// NumberValue returns a numeric rule value (the cvss/epss threshold).
func NumberValue(f float64) *RuleValue { return &RuleValue{Kind: RuleValueNumber, Num: f} }

// AsBool returns the boolean payload; ok is false for a non-boolean value.
func (v RuleValue) AsBool() (b bool, ok bool) {
	if v.Kind != RuleValueBool {
		return false, false
	}
	return v.Bool, true
}

// AsString returns the string payload; ok is false for a non-string value.
func (v RuleValue) AsString() (s string, ok bool) {
	if v.Kind != RuleValueString {
		return "", false
	}
	return v.Str, true
}

// AsNumber returns the numeric payload; ok is false for a non-numeric value.
func (v RuleValue) AsNumber() (f float64, ok bool) {
	if v.Kind != RuleValueNumber {
		return 0, false
	}
	return v.Num, true
}

// UnmarshalJSON decodes a JSON scalar (bool | string | number) into the
// typed RuleValue. null and composite values error.
func (v *RuleValue) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch {
	case s == "null":
		return fmt.Errorf("domain: rule value must not be null")
	case s == "true" || s == "false":
		v.Kind = RuleValueBool
		v.Bool = s == "true"
	case strings.HasPrefix(s, "\""):
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return fmt.Errorf("domain: rule value %s is not a valid string: %w", s, err)
		}
		v.Kind = RuleValueString
		v.Str = str
	default:
		var f float64
		if err := json.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("domain: rule value %s is neither a bool, string nor number", s)
		}
		v.Kind = RuleValueNumber
		v.Num = f
	}
	return nil
}

// MarshalJSON encodes the RuleValue back into its bare JSON scalar.
func (v RuleValue) MarshalJSON() ([]byte, error) {
	switch v.Kind {
	case RuleValueBool:
		return json.Marshal(v.Bool)
	case RuleValueString:
		return json.Marshal(v.Str)
	case RuleValueNumber:
		return json.Marshal(v.Num)
	default:
		return nil, fmt.Errorf("domain: unknown rule value kind %q", v.Kind)
	}
}

// RuleDefinition is one node of the bounded predicate tree (ARCH-004 §1.1):
// either a group (all_of / any_of, recursively) or one atomic condition
// (op + field + operand). A node must be exactly one of the two forms — a
// mixed or empty node is a data error, so an accidental always-true rule
// cannot slip through.
//
// The struct is the typed, JSON-tagged representation of the priority_rules
// definition column; it is never a raw jsonb/pgx type (the domain stays
// DB-agnostic). PriorityRule.Definition is the root node.
type RuleDefinition struct {
	AllOf  []RuleDefinition `json:"all_of,omitempty"`
	AnyOf  []RuleDefinition `json:"any_of,omitempty"`
	Op     RuleOp           `json:"op,omitempty"`
	Field  FactorField      `json:"field,omitempty"`
	Value  *RuleValue       `json:"value,omitempty"`
	Values []string         `json:"values,omitempty"`
}

// EvaluateRule evaluates the predicate definition against the priority
// factors and reports whether it matches. It is pure and deterministic, and
// it validates the whole tree first: an unknown op, field or value — or a
// malformed node — is returned as an error, never silently treated as a
// non-match (ARCH-004 §1.1).
func EvaluateRule(def RuleDefinition, factors PriorityFactors) (bool, error) {
	if err := validateRuleNode(def); err != nil {
		return false, err
	}
	return evalRuleNode(def, factors), nil
}

// validateRuleNode checks one node's shape (group vs atomic) recursively.
func validateRuleNode(n RuleDefinition) error {
	hasGroup := len(n.AllOf) > 0 || len(n.AnyOf) > 0
	hasAtom := n.Op != ""
	switch {
	case hasGroup && hasAtom:
		return fmt.Errorf("domain: rule definition mixes the group (all_of/any_of) and atomic (op) forms")
	case !hasGroup && !hasAtom:
		return fmt.Errorf("domain: rule definition is empty (no all_of, any_of or op)")
	}
	if hasGroup {
		for _, c := range n.AllOf {
			if err := validateRuleNode(c); err != nil {
				return err
			}
		}
		for _, c := range n.AnyOf {
			if err := validateRuleNode(c); err != nil {
				return err
			}
		}
		return nil
	}
	return validateRuleAtom(n)
}

// validateRuleAtom checks one atomic condition against the closed vocabulary.
func validateRuleAtom(n RuleDefinition) error {
	if !n.Op.Valid() {
		return fmt.Errorf("domain: unknown rule op %q", n.Op)
	}
	if !n.Field.Valid() {
		return fmt.Errorf("domain: unknown rule field %q", n.Field)
	}
	switch n.Op {
	case RuleOpEq:
		if n.Value == nil {
			return fmt.Errorf("domain: rule op eq requires a value")
		}
		if len(n.Values) > 0 {
			return fmt.Errorf("domain: rule op eq must not carry values")
		}
		switch n.Field {
		case FieldKEV:
			if _, ok := n.Value.AsBool(); !ok {
				return fmt.Errorf("domain: field %q requires a boolean eq value", n.Field)
			}
		case FieldConfidence, FieldCriticality, FieldExposure:
			s, ok := n.Value.AsString()
			if !ok {
				return fmt.Errorf("domain: field %q requires a string eq value", n.Field)
			}
			if !validFieldValue(n.Field, s) {
				return fmt.Errorf("domain: eq value %q is not a valid %s", s, n.Field)
			}
		default:
			return fmt.Errorf("domain: op eq is not supported for numeric field %q", n.Field)
		}
	case RuleOpIn:
		if n.Value != nil {
			return fmt.Errorf("domain: rule op in must not carry a value")
		}
		if len(n.Values) == 0 {
			return fmt.Errorf("domain: rule op in requires a non-empty values set")
		}
		switch n.Field {
		case FieldConfidence, FieldCriticality, FieldExposure:
			for _, v := range n.Values {
				if !validFieldValue(n.Field, v) {
					return fmt.Errorf("domain: in value %q is not a valid %s", v, n.Field)
				}
			}
		default:
			return fmt.Errorf("domain: op in is not supported for non-string field %q", n.Field)
		}
	case RuleOpGe:
		if len(n.Values) > 0 {
			return fmt.Errorf("domain: rule op ge must not carry values")
		}
		if n.Value == nil {
			return fmt.Errorf("domain: rule op ge requires a numeric value")
		}
		if _, ok := n.Value.AsNumber(); !ok {
			return fmt.Errorf("domain: rule op ge requires a numeric value")
		}
		switch n.Field {
		case FieldCVSS, FieldEPSS:
		default:
			return fmt.Errorf("domain: op ge is not supported for non-numeric field %q", n.Field)
		}
	}
	return nil
}

// validFieldValue reports whether v is a member of the closed value set of
// the string field f (unknown values are errors, never silent non-matches).
func validFieldValue(f FactorField, v string) bool {
	switch f {
	case FieldConfidence:
		_, err := ParseConfidence(v)
		return err == nil
	case FieldCriticality:
		_, err := ParseCriticality(v)
		return err == nil
	case FieldExposure:
		_, err := ParseExposure(v)
		return err == nil
	}
	return false
}

// evalRuleNode evaluates a validated node: all_of must all match, any_of (if
// present) must have at least one match.
func evalRuleNode(n RuleDefinition, f PriorityFactors) bool {
	hasGroup := len(n.AllOf) > 0 || len(n.AnyOf) > 0
	if !hasGroup {
		return evalRuleAtom(n, f)
	}
	for _, c := range n.AllOf {
		if !evalRuleNode(c, f) {
			return false
		}
	}
	if len(n.AnyOf) > 0 {
		for _, c := range n.AnyOf {
			if evalRuleNode(c, f) {
				return true
			}
		}
		return false
	}
	return true
}

// evalRuleAtom evaluates one validated atomic condition.
func evalRuleAtom(n RuleDefinition, f PriorityFactors) bool {
	switch n.Op {
	case RuleOpEq:
		switch n.Field {
		case FieldKEV:
			b, _ := n.Value.AsBool()
			return f.KEV == b
		case FieldConfidence:
			s, _ := n.Value.AsString()
			return string(f.Confidence) == s
		case FieldCriticality:
			s, _ := n.Value.AsString()
			return string(f.Criticality) == s
		case FieldExposure:
			s, _ := n.Value.AsString()
			return string(f.Exposure) == s
		}
	case RuleOpIn:
		var s string
		switch n.Field {
		case FieldConfidence:
			s = string(f.Confidence)
		case FieldCriticality:
			s = string(f.Criticality)
		case FieldExposure:
			s = string(f.Exposure)
		}
		for _, v := range n.Values {
			if v == s {
				return true
			}
		}
		return false
	case RuleOpGe:
		switch n.Field {
		case FieldCVSS:
			x, _ := n.Value.AsNumber()
			return f.CVSS >= x
		case FieldEPSS:
			x, _ := n.Value.AsNumber()
			return f.EPSS >= x
		}
	}
	return false
}
