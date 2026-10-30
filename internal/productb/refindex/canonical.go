package refindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Canonical renders the document as canonical JSON: encoding/json's
// deterministic struct encoding with a two-space indent and a trailing
// newline. Every slice is already sorted/deduplicated by the builder —
// a byte-identical rerun depends on that, not on marshaling.
func Canonical(d *Doc) ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Seal computes hashes.canonical_sha256 — the sha256 of the canonical
// encoding of the document without the hashes field — and stores it.
func Seal(d *Doc) error {
	d.Hashes = nil
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	d.Hashes = &Hashes{CanonicalSHA256: "sha256:" + hex.EncodeToString(sum[:])}
	return nil
}
