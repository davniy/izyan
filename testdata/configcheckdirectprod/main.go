package main

type Claims map[string]interface{}
func (m Claims) VerifyAudience(expected string, req bool) bool {
 audience, _ := m["aud"].(string)
 return req || audience == expected
}
func (m Claims) Valid() bool { return true }
type Config struct { RequireAudience bool }
func main() {
 unused := Config{RequireAudience:false}
 _ = unused
 cfg := Config{RequireAudience:true}
 claims := Claims{}
 claims.VerifyAudience("service",cfg.RequireAudience)
}
