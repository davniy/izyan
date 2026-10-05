package main

import (
	"fmt"

	"example.com/dep/vuln"
	"example.com/yamlconfigprod/config"
)

// AppConfig represents a configuration struct with yaml tags.
type AppConfig struct {
	XPath string `yaml:"xpath"`
}

func loadAppConfig() AppConfig {
	var cfg AppConfig
	return cfg
}

func loadSettings() config.Settings {
	var s config.Settings
	return s
}

func runYaml(cfg AppConfig) {
	fmt.Println(vuln.Parse(cfg.XPath))
}

func runConfigPkg(s config.Settings) {
	u, _ := vuln.ParseURI(s.Query)
	fmt.Println(u)
}

func main() {
	cfg := loadAppConfig()
	runYaml(cfg)

	s := loadSettings()
	runConfigPkg(s)
}
