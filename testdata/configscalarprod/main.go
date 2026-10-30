package main

type Config struct { Enabled bool }
const disabled = false
func consume(v bool) {}
func main() {
	unused := Config{Enabled: true}
	_ = unused
	cfg := Config{Enabled: disabled}
	consume(cfg.Enabled)
	var zero Config
	consume(zero.Enabled)
}
