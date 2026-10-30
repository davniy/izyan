package check

// Claims mirrors the jwt-go MapClaims shape: a map-backed claims receiver
// whose check member indexes a receiver field.
type Claims map[string]interface{}

// VerifyAudience is the affected check: its argument req controls whether the
// comparison is enforced, and its payload is the receiver's "aud" field.
func (m Claims) VerifyAudience(cmp string, req bool) bool {
	aud, _ := m["aud"].(string)
	return verifyAud(aud, cmp, req)
}

func verifyAud(aud, cmp string, req bool) bool {
	if req {
		return true
	}
	return aud == cmp
}

// Valid is the live sibling validation pipeline.
func (m Claims) Valid() error { return nil }

// Parse exercises the live pipeline so the receiver has a product call site.
func Parse() error {
	m := Claims{}
	return m.Valid()
}
