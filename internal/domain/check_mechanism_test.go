package domain

import (
	"go/types"
	"reflect"
	"testing"
)

func TestCheckMechanismText(t *testing.T) {
	t.Run("description takes precedence over summary", func(t *testing.T) {
		v := Vulnerability{
			ID:          "GO-TEST-1",
			Summary:     "Summary statement",
			Description: "Description statement",
		}
		if got := CheckMechanismText(v); got != "Description statement" {
			t.Fatalf("got %q; want %q", got, "Description statement")
		}
	})

	t.Run("summary used when description is empty or whitespace", func(t *testing.T) {
		v := Vulnerability{
			ID:          "GO-TEST-2",
			Summary:     "Summary fallback statement",
			Description: "   \n\t  ",
		}
		if got := CheckMechanismText(v); got != "Summary fallback statement" {
			t.Fatalf("got %q; want %q", got, "Summary fallback statement")
		}
	})

	t.Run("both empty returns empty string", func(t *testing.T) {
		v := Vulnerability{
			ID: "GO-TEST-3",
		}
		if got := CheckMechanismText(v); got != "" {
			t.Fatalf("got %q; want empty string", got)
		}
	})
}

func TestParseCheckMechanism(t *testing.T) {
	check := SymbolRef{Package: "example.com/dep/check", Symbol: "Claims.VerifyAudience"}

	t.Run("extracts invocation and payload shapes", func(t *testing.T) {
		text := "If a token contains an audience claim with an array of strings, rather than a single string, " +
			"and Claims.VerifyAudience is called with req set to false, then audience verification will be bypassed."
		stmts := ParseCheckMechanism(text, check)
		if !stmts.Invocation {
			t.Fatal("expected invocation=true")
		}
		if stmts.Omission {
			t.Fatal("expected omission=false")
		}
		if stmts.ArgName != "req" {
			t.Fatalf("ArgName = %q; want req", stmts.ArgName)
		}
		if stmts.ArgValue != "false" {
			t.Fatalf("ArgValue = %q; want false", stmts.ArgValue)
		}
		if stmts.ClaimWord != "audience" {
			t.Fatalf("ClaimWord = %q; want audience", stmts.ClaimWord)
		}
		if len(stmts.Shapes) != 1 || stmts.Shapes[0] != "array" {
			t.Fatalf("Shapes = %v; want [array]", stmts.Shapes)
		}
		if len(stmts.ExcludedShapes) != 1 || stmts.ExcludedShapes[0] != "string" {
			t.Fatalf("ExcludedShapes = %v; want [string]", stmts.ExcludedShapes)
		}
		if stmts.ConflictingInvocation {
			t.Fatal("expected no conflicting invocation")
		}
		if stmts.ConflictingPayload {
			t.Fatal("expected no conflicting payload")
		}
	})

	t.Run("extracts omission statement and negation", func(t *testing.T) {
		text := "MapClaims.VerifyAudience is not called by MapClaims.Valid, so verification is omitted."
		checkRef := SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"}
		stmts := ParseCheckMechanism(text, checkRef)
		if !stmts.Omission {
			t.Fatal("expected omission=true")
		}
		if stmts.Invocation {
			t.Fatal("expected invocation=false")
		}
		if stmts.OmissionQuote == "" {
			t.Fatal("expected non-empty omission quote")
		}

		// Negated omission: "is not omitted"
		negatedText := "Claims.VerifyAudience is not omitted during processing."
		stmtsNeg := ParseCheckMechanism(negatedText, check)
		if stmtsNeg.Omission {
			t.Fatal("negated omission must not set omission=true")
		}
	})

	t.Run("detects conflicting invocation statements", func(t *testing.T) {
		text := "Claims.VerifyAudience is called with req set to false. Claims.VerifyAudience is called with req set to true."
		stmts := ParseCheckMechanism(text, check)
		if !stmts.Invocation {
			t.Fatal("expected invocation=true")
		}
		if !stmts.ConflictingInvocation {
			t.Fatal("expected ConflictingInvocation=true for conflicting literals")
		}
	})

	t.Run("detects conflicting invocation argument names", func(t *testing.T) {
		text := "Claims.VerifyAudience is called with req set to false. Claims.VerifyAudience is called with opt set to false."
		stmts := ParseCheckMechanism(text, check)
		if !stmts.ConflictingInvocation {
			t.Fatal("expected ConflictingInvocation=true for conflicting parameter names")
		}
	})

	t.Run("detects conflicting payload claims", func(t *testing.T) {
		text := "Claims.VerifyAudience handles an audience claim with an array of strings. " +
			"Claims.VerifyAudience handles an issuer claim with a slice of strings."
		stmts := ParseCheckMechanism(text, check)
		if !stmts.ConflictingPayload {
			t.Fatal("expected ConflictingPayload=true for different claim words")
		}
	})

	t.Run("advisory without check mention does not extract check invocation", func(t *testing.T) {
		text := "OtherFunc is called with req set to false."
		stmts := ParseCheckMechanism(text, check)
		if stmts.Invocation {
			t.Fatal("invocation extracted for unmentioned check")
		}
	})
}

func TestBindCheckArgumentPredicate(t *testing.T) {
	formals := []string{"token", "req", "issuer"}

	t.Run("successful binding with case-insensitive name and normalized boolean", func(t *testing.T) {
		stmts := CheckMechanismStatements{
			Invocation: true,
			ArgName:    "REQ",
			ArgValue:   " `false` ",
		}
		pred, err := BindCheckArgumentPredicate(stmts, formals)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pred.Name != "req" {
			t.Fatalf("Name = %q; want req", pred.Name)
		}
		if pred.Index != 1 {
			t.Fatalf("Index = %d; want 1", pred.Index)
		}
		if pred.Value != "false" {
			t.Fatalf("Value = %q; want false", pred.Value)
		}
	})

	t.Run("successful binding for true literal", func(t *testing.T) {
		stmts := CheckMechanismStatements{
			Invocation: true,
			ArgName:    "req",
			ArgValue:   "true",
		}
		pred, err := BindCheckArgumentPredicate(stmts, formals)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pred.Value != "true" || pred.Index != 1 {
			t.Fatalf("unexpected pred: %+v", pred)
		}
	})

	t.Run("preserves arbitrary normalized literals without boolean coercion", func(t *testing.T) {
		for _, literal := range []string{"1", "0", "yes", "no", "TRUE_VAL", "2", " 'MixedCase' ", "\"TOKEN\"", "`+1.5`"} {
			stmts := CheckMechanismStatements{Invocation: true, ArgName: "req", ArgValue: literal}
			pred, err := BindCheckArgumentPredicate(stmts, formals)
			if err != nil || pred.Value != normalizeAdvisoryLiteral(literal) || pred.Name != "req" || pred.Index != 1 {
				t.Fatalf("literal %q: predicate=%+v err=%v", literal, pred, err)
			}
		}
	})

	t.Run("counterexample: rejects undeclared formal parameter", func(t *testing.T) {
		stmts := CheckMechanismStatements{
			Invocation: true,
			ArgName:    "nonExistentParam",
			ArgValue:   "false",
		}
		_, err := BindCheckArgumentPredicate(stmts, formals)
		if err == nil {
			t.Fatal("expected error for undeclared parameter")
		}
	})

	t.Run("counterexample: rejects missing argument name or literal", func(t *testing.T) {
		stmts := CheckMechanismStatements{
			Invocation: true,
			ArgName:    "",
			ArgValue:   "false",
		}
		_, err := BindCheckArgumentPredicate(stmts, formals)
		if err == nil {
			t.Fatal("expected error for missing argument name")
		}

		stmts.ArgName = "req"
		stmts.ArgValue = ""
		_, err = BindCheckArgumentPredicate(stmts, formals)
		if err == nil {
			t.Fatal("expected error for missing literal")
		}
	})

	t.Run("counterexample: rejects conflicting invocation statements", func(t *testing.T) {
		stmts := CheckMechanismStatements{
			Invocation:            true,
			ConflictingInvocation: true,
			ArgName:               "req",
			ArgValue:              "false",
		}
		_, err := BindCheckArgumentPredicate(stmts, formals)
		if err == nil {
			t.Fatal("expected error for conflicting invocations")
		}
	})
}

// These expectations pin the pre-extraction builder grammar, including its
// intentionally narrow recognition and exact sentence quotations.
func TestCheckMechanismGrammarParity(t *testing.T) {
	check := SymbolRef{Symbol: "Claims.VerifyAudience"}
	for _, tc := range []struct {
		name string
		text string
		want CheckMechanismStatements
	}{
		{"quoted invocation", "  Claims.VerifyAudience was called with `REQ` == `FALSE`!  ", CheckMechanismStatements{Invocation: true, ArgName: "REQ", ArgValue: "FALSE", Quote: "Claims.VerifyAudience was called with `REQ` == `FALSE`!", Effect: "Claims.VerifyAudience was called with `REQ` == `FALSE`!"}},
		{"method name boundary", "OtherVerifyAudience is called with req=false.", CheckMechanismStatements{}},
		{"case sensitive symbol", "verifyaudience is called with req=false.", CheckMechanismStatements{}},
		{"unsupported invocation wording", "Claims.VerifyAudience is invoked with req=false.", CheckMechanismStatements{}},
		{"omission quote", "Claims.VerifyAudience does not execute; Claims.VerifyAudience was never called.", CheckMechanismStatements{Omission: true, Quote: "Claims.VerifyAudience does not execute", OmissionQuote: "Claims.VerifyAudience does not execute"}},
		{"negated omission", "Claims.VerifyAudience is not omitted. Claims.VerifyAudience is never omitted. Claims.VerifyAudience is not missing. Claims.VerifyAudience is not absent. Claims.VerifyAudience has no omission.", CheckMechanismStatements{}},
		{"fallback payload first sentence", "The audience claim is a []string rather than string. The issuer claim is a slice.", CheckMechanismStatements{ClaimWord: "audience", Shapes: []string{"array"}, ExcludedShapes: []string{"string"}}},
		{"payload exclusion conflict", "Claims.VerifyAudience accepts an audience claim array. Claims.VerifyAudience accepts an audience claim array, not a string.", CheckMechanismStatements{ClaimWord: "audience", Shapes: []string{"array"}, ConflictingPayload: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseCheckMechanism(tc.text, check); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v; want %+v", got, tc.want)
			}
		})
	}
	for _, sep := range []string{". ", "!\t", "?\n", ";", "\n"} {
		first := "Claims.VerifyAudience is called with req=`FALSE`"
		last := "VerifyAudience is called with REQ=`false`."
		got := ParseCheckMechanism(first+sep+last, check)
		if !got.Invocation || got.ConflictingInvocation || got.Quote != last || got.Effect != last {
			t.Fatalf("separator %q changed normalized agreement or last quote: %+v", sep, got)
		}
	}
	got := ParseCheckMechanism("Claims.VerifyAudience is not called.\nVerifyAudience is called with req=+1.5.", check)
	if !got.Invocation || !got.Omission || got.ArgValue != "+1.5." || got.OmissionQuote != "Claims.VerifyAudience is not called." || got.Quote != "VerifyAudience is called with req=+1.5." {
		t.Fatalf("mixed statements or decimal punctuation changed: %+v", got)
	}
}

func TestCheckArgumentTypedFormalMapping(t *testing.T) {
	// Replay obtains formal names from a captured *types.Func signature, while
	// the builder supplies SymbolSignature.Params. Both must produce the same
	// declared name/index/value without introducing a receiver offset.
	params := types.NewTuple(
		types.NewVar(0, nil, "aud", types.Typ[types.String]),
		types.NewVar(0, nil, "req", types.Typ[types.Bool]),
	)
	sig := types.NewSignatureType(nil, nil, nil, params, nil, false)
	fn := types.NewFunc(0, nil, "VerifyAudience", sig)
	var names []string
	for i := range fn.Type().(*types.Signature).Params().Len() {
		names = append(names, fn.Type().(*types.Signature).Params().At(i).Name())
	}
	stmts := ParseCheckMechanism("VerifyAudience is called with REQ set to `FALSE`", SymbolRef{Symbol: "Claims.VerifyAudience"})
	want := CheckArgumentPredicate{Name: "req", Index: 1, Value: "false"}
	for _, formals := range [][]string{names, {"aud", "req"}} {
		got, err := BindCheckArgumentPredicate(stmts, formals)
		if err != nil || got != want {
			t.Fatalf("binding %v: got %+v err=%v; want %+v", formals, got, err, want)
		}
	}
	for _, formals := range [][]string{{"req", "aud"}, {"aud", "renamed"}} {
		got, err := BindCheckArgumentPredicate(stmts, formals)
		if err == nil && got == want {
			t.Fatalf("changed formal signature reproduced original predicate: %v", formals)
		}
	}
	for _, text := range []string{"VerifyAudience is called with aud=false", "VerifyAudience is called with req=true"} {
		got, err := BindCheckArgumentPredicate(ParseCheckMechanism(text, SymbolRef{Symbol: "Claims.VerifyAudience"}), names)
		if err == nil && got == want {
			t.Fatalf("edited argument reproduced original predicate: %q", text)
		}
	}
}
