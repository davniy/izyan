package main

import (
	"encoding/json"
	"flag"
	"os"
	"reflect"
)
type Options struct { Enabled bool }
func consume(v bool) {}
func mutate(v *Options) { v.Enabled = true }
func main() {
	defaults := Options{Enabled: false}
	cfg := defaults
	alias := &cfg
	alias.Enabled = os.Getenv("ENABLE") == "yes"
	flag.BoolVar(&cfg.Enabled, "enable", false, "enable")
	data, _ := os.ReadFile("settings.json")
	_ = json.Unmarshal(data, &cfg)
	mutate(&cfg)
	reflect.ValueOf(&cfg).Elem().Field(0).SetBool(true)
	callback := mutate
	callback(&cfg)
	consume(cfg.Enabled)
}
