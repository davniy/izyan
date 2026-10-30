package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// maxDeclaredAssumptionsBytes bounds the operator-supplied assumptions
// document: it is a static policy sidecar — anything larger is
// malformed input, never a truncated member.
const maxDeclaredAssumptionsBytes = int64(1) << 16

// LoadDeclaredAssumptions reads and validates a declared-assumptions/1
// document supplied via --declared-assumptions and returns it as the
// typed channel record. nil for an empty path — the channel was never
// requested. Every failure — unreadable file, oversized document,
// credential-bearing key, unknown JSON field, wrong schema, duplicate
// id, invalid date, invalid digest, unsupported kind, empty required
// field, expired or scope-inconsistent member — is a typed LoadError on
// the returned record: the channel fails closed, never a silent skip
// and never a partial document. The returned members remain available
// for audit even under LoadError; admission (domain.AdmitAssumption)
// still re-validates them at consume time.
func LoadDeclaredAssumptions(path string) *domain.DeclaredAssumptionsInput {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	rec := &domain.DeclaredAssumptionsInput{Path: ProvenanceLocalRef(path)}
	fail := func(code string) *domain.DeclaredAssumptionsInput {
		rec.LoadError = code
		return rec
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return fail(domain.AssumptionsLoadUnreadable)
	}
	if info.Size() > maxDeclaredAssumptionsBytes {
		return fail(domain.AssumptionsLoadOversized)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(domain.AssumptionsLoadUnreadable)
	}
	sum := sha256.Sum256(raw)
	rec.SHA256 = hex.EncodeToString(sum[:])
	if metadataCredentialKeyRe.Match(raw) {
		return fail(domain.AssumptionsLoadInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc domain.DeclaredAssumptionsDocument
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return fail(domain.AssumptionsLoadInvalid)
	}
	rec.Schema = doc.Schema
	rec.ContentDigest = doc.ContentDigest
	rec.Assumptions = doc.Assumptions
	if err := domain.ValidateDeclaredAssumptions(&doc); err != nil {
		return fail(domain.AssumptionsLoadInvalid)
	}
	return rec
}
