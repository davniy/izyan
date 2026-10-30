package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/davniy/izyan/internal/research"
)

// runResearchHistory is deliberately independent of the live research and
// triage option loaders: historical playback needs neither a checkout nor a
// model environment and cannot publish a current report.
func runResearchHistory(args []string) error {
	fs := flag.NewFlagSet("eval research-replay", flag.ContinueOnError)
	var run, out string
	fs.StringVar(&run, "run", "", "saved research /1–/4 run directory")
	fs.StringVar(&out, "out", "", "new historical playback directory")
	if err := fs.Parse(args); err != nil { return err }
	if run == "" || out == "" || fs.NArg() != 0 { return fmt.Errorf("research-replay requires --run <saved-run> --out <new-directory> and no positional arguments") }
	history, err := research.PrepareHistoricalReplay(context.Background(), run)
	if err != nil { return err }
	return history.Write(out)
}
