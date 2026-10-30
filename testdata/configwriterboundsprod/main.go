package main

type Config struct { Enabled bool; Other int }
type Foreign struct { Enabled bool; Other int }
func (c *Config) Enable() { c.Enabled = true }
func loadConfig() (error, Config) { return nil, Config{Enabled: true} }
func consume(v bool) {}
func main() {
	empty := Config{}
	omitted := Config{Other: 1}
	foreign := Foreign{Other: 1}
	_ = foreign
	consume(empty.Enabled)
	consume(omitted.Enabled)
	var _, tuple = loadConfig()
	consume(tuple.Enabled)
	rangedField := Config{Enabled: false}
	for _, rangedField.Enabled = range []bool{true} { consume(rangedField.Enabled) }
	rangedObject := Config{Enabled: false}
	for _, rangedObject = range []Config{{Enabled: true}} { consume(rangedObject.Enabled) }
	captured := Config{Enabled: false}
	mutate := captured.Enable
	mutate()
	consume(captured.Enabled)
	directReceiver := Config{Enabled: false}
	directReceiver.Enable()
	parenthesizedReceiver := Config{Enabled: false}
	(parenthesizedReceiver.Enable)()
	multiline := Config{Enabled: false}
	consume(
		multiline.Enabled,
	)
	// The selector starts on a different line from the canonical call paren.
	getConsumer().
		Use(multiline.Enabled)
}
type Consumer struct{}
func getConsumer() Consumer { return Consumer{} }
func (Consumer) Use(v bool) {}
