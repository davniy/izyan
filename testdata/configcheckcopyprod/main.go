package main

import "example.com/configissuer/check"

type Options struct { Skip bool }
const enforce = false
func main() {
 defaults := Options{Skip:false}
 cfg := defaults
 defaults.Skip = true
 cfg.Skip = enforce
 context := check.Context{}
 context.VerifyIssuer(cfg.Skip,"service")
 context.VerifyIssuer((cfg.Skip),"another")
}
