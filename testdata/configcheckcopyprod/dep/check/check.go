package check

type Context map[string]interface{}
func (m Context) VerifyIssuer(skip bool, expected string) bool {
 issuer, _ := m["iss"].(string)
 return skip || issuer == expected
}
func (m Context) Valid() bool { return true }
