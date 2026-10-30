// Package research is the frozen B1 evaluation arm.
//
// It is an evaluation control, not a product runtime. It renders one pinned
// prompt, launches one containerized agent turn against a pinned snapshot and
// records the raw answer plus the host-fact consistency layer. It never
// produces a verified safety conclusion, never closes a vulnerability and is
// never a second live human investigator: `izyan triage` owns that loop, and
// `izyan research` owns the deterministic evidence/proof lane.
//
// The arm is reachable only through `izyan eval research-b1`. Its prompt
// (b1-plain.txt), model key, container image and config extension are frozen
// evaluation assets: changing them changes the experiment, so they are kept
// byte-stable rather than parameterized by production configuration.
package research
