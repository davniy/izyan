package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---- attempt / output capture ----

// captureOutput records the retained agent output verbatim (or the
// NOT_REQUESTED record when no turn ran). It is a capture step, never a
// merge: the preserved answer, its status and its artifacts are copied
// as recorded, and the linkage members are filled by applyAttempts.
func (a *assembler) captureOutput(r *Report, in AssembleInput) {
	if in.Turn != nil {
		r.AgentOutput = in.Turn.Output
		return
	}
	r.AgentOutput = AgentOutput{Status: AgentNotRequested, RawArtifact: AgentRawArtifact{}}
}

// applyAttempts builds the run.attempts ledger: one row for the
// deterministic lane and one for the agent attempt (or a NOT_REQUESTED
// record), and wires the persisted linkage members of agent_output.
// Originals are never overwritten; each attempt owns a distinct
// directory. The ledger is historical capture: it records what ran,
// never a conclusion.
func (a *assembler) applyAttempts(r *Report, in AssembleInput) {
	detStart := in.LaneStartedAt
	if detStart.IsZero() {
		detStart = in.StartedAt
	}
	detEnd := in.LaneFinishedAt
	if detEnd.IsZero() {
		detEnd = in.FinishedAt
	}
	det := Attempt{
		ID: fmt.Sprintf("attempt-%04d", 1), Kind: "deterministic", Ordinal: 1,
		Status:     "OK",
		StartedAt:  detStart.UTC().Format(time.RFC3339),
		FinishedAt: detEnd.UTC().Format(time.RFC3339),
		ReasonCode: AttemptReasonInitial,
		Reason:     "initial deterministic lane pass (strict evidencetools session)",
		RetryOf:    nil, OriginalPreserved: true,
		Extraction: &Extraction{
			Status: ExtractionNotApplicable, InvalidReason: InvalidNone,
			Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
		},
	}
	if a.lane.FactsArtifact != nil {
		det.ResultArtifact = a.lane.FactsArtifact
	}
	r.Run.Attempts = append(r.Run.Attempts, det)
	// Agent attempt.
	ag := Attempt{
		ID: fmt.Sprintf("attempt-%04d", 2), Kind: "agent", Ordinal: 2,
		ReasonCode: AttemptReasonInitial,
		RetryOf:    nil, OriginalPreserved: true,
	}
	t := in.Turn
	switch {
	case t == nil:
		ag.Status = AgentNotRequested
		ag.ReasonCode = AttemptReasonOther
		ag.Reason = "agent not requested (deterministic evidence/proof lane)"
		ag.StartedAt = detEnd.UTC().Format(time.RFC3339)
		ag.FinishedAt = detEnd.UTC().Format(time.RFC3339)
		ag.Extraction = &Extraction{
			Status: ExtractionNotApplicable, InvalidReason: InvalidNone,
			Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
		}
	case t.ReplayedAttempt != nil:
		// The turn was rebuilt from persisted artifacts: the ledger row
		// keeps the saved id/status/timestamps/extraction verbatim; only
		// the bookkeeping fields are rewritten for this replay run.
		// retry_of is dropped on purpose: the replayed row's original
		// siblings are not part of this run's ledger, so the saved
		// pointer would dangle.
		saved := *t.ReplayedAttempt
		ag.ID = saved.ID
		ag.Ordinal = saved.Ordinal
		if ag.Ordinal <= det.Ordinal {
			ag.Ordinal = det.Ordinal + 1
		}
		ag.Status = saved.Status
		ag.StartedAt = saved.StartedAt
		ag.FinishedAt = saved.FinishedAt
		ag.ReasonCode = AttemptReasonManualRecheck
		ag.Reason = firstN(fmt.Sprintf("replayed from persisted artifacts (%s); no model call",
			t.Output.ReplayedFrom.Dir), 300)
		ag.RetryOf = nil
		ag.ResultArtifact = saved.ResultArtifact
		ag.Extraction = saved.Extraction
	default:
		ag.Status = t.Output.Status
		st, fin := t.StartedAt, t.FinishedAt
		if st.IsZero() {
			st = detEnd
		}
		if fin.IsZero() {
			fin = in.FinishedAt
		}
		ag.StartedAt = st.UTC().Format(time.RFC3339)
		ag.FinishedAt = fin.UTC().Format(time.RFC3339)
		switch t.Output.Status {
		case AgentOK:
			ag.Reason = "initial agent assessment"
		case AgentInvalidFormat:
			ag.ReasonCode = AttemptReasonInvalidExtraction
			ag.Reason = firstN("answer extraction failed: "+t.Err, 300)
		case AgentTimeout:
			ag.ReasonCode = AttemptReasonTimeout
			ag.Reason = firstN("attempt timed out: "+t.Err, 300)
		case AgentProviderRefused:
			ag.ReasonCode = AttemptReasonProviderRefused
			ag.Reason = firstN("provider refused: "+t.Err, 300)
		default:
			ag.ReasonCode = AttemptReasonInfrastructureFailure
			ag.Reason = firstN("attempt failed: "+t.Err, 300)
		}
		if t.ResultArtifact != nil {
			ag.ResultArtifact = t.ResultArtifact
		}
		if t.Extraction != nil {
			ag.Extraction = t.Extraction
		} else {
			ag.Extraction = &Extraction{
				Status: ExtractionInvalid, InvalidReason: InvalidNoCandidate,
				Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
			}
		}
	}
	r.Run.Attempts = append(r.Run.Attempts, ag)
	// agent_output wiring (output object was set at applySlice2 entry;
	// only linkage fields are filled here). A replayed turn keeps every
	// saved member verbatim — the ledger row it resolves to is the
	// persisted one, so only attempt_id linkage is (re)asserted.
	if t == nil {
		return
	}
	r.AgentOutput.AttemptID = strPtr(ag.ID)
	if t.ReplayedAttempt != nil {
		if r.AgentOutput.Extraction == nil {
			r.AgentOutput.Extraction = ag.Extraction
		}
		return
	}
	r.AgentOutput.ResultArtifact = ag.ResultArtifact
	if r.AgentOutput.Extraction == nil {
		r.AgentOutput.Extraction = ag.Extraction
	}
	if r.AgentOutput.AnswerArtifact == nil && ag.Extraction != nil {
		r.AgentOutput.AnswerArtifact = ag.Extraction.AnswerArtifact
	}
}

// ---- strict answer extraction (§2.7) ----

// answerCandidate is a raw JSON object candidate found in the answer.
type answerCandidate struct {
	raw   []byte
	start int
	end   int
	probe struct {
		Category   string          `json:"category"`
		Reasoning  string          `json:"reasoning"`
		Assessment json.RawMessage `json:"assessment"`
	}
	hasCategory   bool
	category      string
	reasoning     string
	canon         []byte
	rawSHA        string
	canonSHA      string
	candidateOK   bool   // candidate-shaped (category member present)
	schemaProblem string // invalid reason when not VALID
}

// strictExtract is the single answer-extraction entry point (§2.7) used
// identically by the live path (agent.go) and replay (replay.go): the
// strict pass runs first, unchanged in semantics; bounded recovery is
// attempted only when the strict pass retained zero candidates, and the
// strict INVALID record is kept verbatim when recovery does not apply.
func strictExtract(text string) (*agentAnswer, *Extraction) {
	ans, ext := strictScan(text)
	if ans != nil {
		return ans, ext
	}
	if ext.CandidateCount == 0 {
		if rans, rext := recoverExtract(text); rans != nil {
			return rans, rext
		}
	}
	return ans, ext
}

// strictScan scans the retained answer text for every complete JSON
// object candidate (§2.7): candidate-shaped objects are validated, all
// candidates are recorded, and multiple conflicting VALID candidates
// make the extraction INVALID instead of silently taking the first.
func strictScan(text string) (*agentAnswer, *Extraction) {
	ext := &Extraction{
		Status: ExtractionValid, InvalidReason: InvalidNone,
		Candidates: []ExtractionCandidate{}, SelectedIndex: -1,
	}
	var cands []*answerCandidate
	skipUntil := -1
	for i := range len(text) {
		if i < skipUntil {
			continue
		}
		if text[i] != '{' {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(text[i:]))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			continue
		}
		end := i + len(raw) // raw is the exact balanced object bytes
		c := &answerCandidate{raw: raw, start: i, end: end}
		if json.Unmarshal(raw, &c.probe) == nil {
			c.candidateOK = c.probe.Category != ""
			c.category = c.probe.Category
			c.reasoning = c.probe.Reasoning
			if !c.candidateOK && len(c.probe.Assessment) > 0 {
				var inner struct {
					Category  string `json:"category"`
					Reasoning string `json:"reasoning"`
				}
				if json.Unmarshal(c.probe.Assessment, &inner) == nil && inner.Category != "" {
					c.candidateOK = true
					c.category = inner.Category
					c.reasoning = inner.Reasoning
				}
			}
		}
		if !c.candidateOK {
			continue // non-candidate-shaped JSON values are ignored
		}
		rs := sha256.Sum256(raw)
		c.rawSHA = hex.EncodeToString(rs[:])
		var norm any
		if json.Unmarshal(raw, &norm) == nil {
			c.canon, _ = json.Marshal(norm)
		} else {
			c.canon = raw
		}
		cs := sha256.Sum256(c.canon)
		c.canonSHA = hex.EncodeToString(cs[:])
		cands = append(cands, c)
		// A candidate-shaped object owns its interior: nested members
		// (e.g. assessment.category) are part of the same candidate,
		// never competing ones — skip to its closing brace.
		skipUntil = end
	}
	for _, c := range cands {
		switch {
		case c.category == "":
			c.schemaProblem = InvalidMissingCategory
		case !validCategories[strings.ToLower(c.category)]:
			c.schemaProblem = InvalidSchema
		case strings.TrimSpace(c.reasoning) == "":
			c.schemaProblem = InvalidMissingReasoning
		}
	}
	// Rank: VALID first, else the first invalid reason by precedence.
	var firstValid int = -1
	canonSeen := map[string]bool{}
	distinctValid := 0
	for i, c := range cands {
		if c.schemaProblem != "" {
			continue
		}
		if !canonSeen[c.canonSHA] {
			canonSeen[c.canonSHA] = true
			distinctValid++
		}
		if firstValid < 0 {
			firstValid = i
		}
	}
	// Emit candidate rows.
	for i, c := range cands {
		row := ExtractionCandidate{
			Index: i, Status: "VALID",
			RawSHA256: c.rawSHA, CanonicalSHA256: c.canonSHA,
			Selector: fmt.Sprintf("bytes %d..%d of retained answer", c.start, c.end),
		}
		if c.schemaProblem != "" {
			row.Status = "INVALID"
		}
		if c.category != "" {
			row.Category = strPtr(strings.ToLower(c.category))
		}
		ext.Candidates = append(ext.Candidates, row)
	}
	ext.CandidateCount = len(cands)
	switch {
	case distinctValid > 1:
		ext.Status = ExtractionInvalid
		ext.InvalidReason = InvalidAmbiguous
	case len(cands) == 0:
		ext.Status = ExtractionInvalid
		ext.InvalidReason = InvalidNoCandidate
	case firstValid < 0:
		ext.Status = ExtractionInvalid
		// precedence: malformed > missing category > schema > reasoning
		order := []string{InvalidMalformedJSON, InvalidMissingCategory, InvalidSchema, InvalidMissingReasoning}
		for _, want := range order {
			for _, c := range cands {
				if c.schemaProblem == want {
					ext.InvalidReason = want
					break
				}
			}
			if ext.InvalidReason != InvalidNone {
				break
			}
		}
		if ext.InvalidReason == InvalidNone {
			ext.InvalidReason = InvalidMalformedJSON
		}
	default:
		ext.SelectedIndex = firstValid
	}
	if ext.Status == ExtractionInvalid {
		return nil, ext
	}
	sel := cands[firstValid]
	var ans agentAnswer
	if err := json.Unmarshal(sel.raw, &ans); err != nil {
		ext.Status = ExtractionInvalid
		ext.InvalidReason = InvalidMalformedJSON
		ext.SelectedIndex = -1
		return nil, ext
	}
	if ans.Category == "" && len(ans.Assessment) > 0 {
		var inner struct {
			Category  string `json:"category"`
			Reasoning string `json:"reasoning"`
		}
		if json.Unmarshal(ans.Assessment, &inner) == nil {
			ans.Category = inner.Category
			if ans.Reasoning == "" {
				ans.Reasoning = inner.Reasoning
			}
		}
	}
	ans.Category = strings.ToLower(ans.Category)
	return &ans, ext
}

// ---- bounded extractor recovery (§2.7) ----

// objectRegion is one top-level object span in the answer text: closed
// regions end at their balancing '}'. A region left dangling at EOF
// carries its unmatched-brace count (unclosed) and whether the text
// ended inside a quoted string (inStringAtEnd), which bounds which
// recovery may apply. Recovery never fabricates string content.
type objectRegion struct {
	start         int
	end           int
	closed        bool
	unclosed      int
	inStringAtEnd bool
}

// scanObjectRegions walks the answer text tracking quoted strings and
// escapes, and returns every top-level '{'…'}' span: braces inside
// quoted strings never count, a '}' with no open object is ignored, and
// a region left open at EOF is reported with its unmatched depth.
// Nested objects belong to the enclosing region — ambiguity across
// separate complete objects is decided by the strict pass, not here.
func scanObjectRegions(text string) []objectRegion {
	var regions []objectRegion
	depth, start := 0, -1
	inStr, esc := false, false
	for i := range len(text) {
		c := text[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 {
					regions = append(regions, objectRegion{
						start: start, end: i + 1, closed: true,
					})
					start = -1
				}
			}
		}
	}
	if start >= 0 {
		regions = append(regions, objectRegion{
			start: start, end: len(text),
			unclosed: depth, inStringAtEnd: inStr,
		})
	}
	return regions
}

// assessmentUnclosed reports whether a dangling object region's depth-1
// `assessment` member holds containers still open at EOF — i.e. the
// unmatched structure lies inside the assessment value and brace
// completion would fabricate assessment content. A fully-decodable
// assessment value means every dangling open belongs to a later member,
// never to assessment. A key repeated at depth 1 counts as damaged:
// JSON unmarshal last-wins, but recovery must not pick a side.
func assessmentUnclosed(text string, rg objectRegion) bool {
	depth := 1
	inStr, esc := false, false
	for i := rg.start + 1; i < rg.end; {
		c := text[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			i++
			continue
		}
		switch c {
		case '"':
			var raw json.RawMessage
			if err := json.NewDecoder(strings.NewReader(text[i:rg.end])).Decode(&raw); err != nil {
				inStr = true
				i++
				continue
			}
			tokEnd := i + len(raw)
			var key string
			if json.Unmarshal(raw, &key) == nil && key == "assessment" && depth == 1 {
				j := tokEnd
				for j < rg.end && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r') {
					j++
				}
				if j < rg.end && text[j] == ':' {
					j++
					for j < rg.end && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r') {
						j++
					}
					// The value must consume the complete member bytes:
					// a parseable prefix followed by stray bytes is a
					// damaged member, not an intact assessment.
					var val json.RawMessage
					if err := json.NewDecoder(strings.NewReader(text[j:rg.end])).Decode(&val); err == nil {
						k := j + len(val)
						for k < rg.end && jsonWS(text[k]) {
							k++
						}
						if k == rg.end || text[k] == ',' || text[k] == '}' || text[k] == ']' {
							return false // assessment value intact — dangling opens belong elsewhere
						}
					}
					// Damaged member (no decodable value, or stray bytes
					// after one): count containers still open inside its
					// span at EOF. Any positive balance means the
					// dangling structure sits inside assessment.
					bal := 0
					sin, ses := false, false
					for k := j; k < rg.end; k++ {
						d := text[k]
						if sin {
							switch {
							case ses:
								ses = false
							case d == '\\':
								ses = true
							case d == '"':
								sin = false
							}
							continue
						}
						switch d {
						case '"':
							sin = true
						case '{', '[':
							bal++
						case '}', ']':
							bal--
						}
					}
					return bal > 0
				}
			}
			i = tokEnd
		case '{', '[':
			depth++
			i++
		case '}', ']':
			depth--
			i++
			if depth < 1 {
				return false
			}
		default:
			i++
		}
	}
	return false
}

// recoverExtract runs the bounded recovery ladder after a strict pass
// that found zero candidates. On success it returns the recovered answer
// plus an Extraction record whose Recovery field names the repair; on
// failure it returns (nil, nil) so the caller keeps the strict INVALID
// record verbatim. Recovery is deliberately narrow: no first-parseable-
// JSON acceptance, no backslash deletion, no key re-quoting, no bracket
// repair, and an unterminated reasoning is never rescued by prefix.
func recoverExtract(text string) (*agentAnswer, *Extraction) {
	regions := scanObjectRegions(text)
	if len(regions) == 0 {
		return nil, nil
	}
	// Bounded brace completion: only a dangling object missing 1–2
	// closing braces at EOF qualifies, and never when the text ends
	// inside a quoted string (closing the object would embed the
	// appended braces in an unterminated string). The unmatched braces
	// must also sit outside the assessment member: completing a
	// truncated assessment fabricates the payload the report later
	// consumes, which is exactly the member repair this recovery is not
	// allowed to perform — such damage falls through to member salvage,
	// where assessment survives only when its original bytes parse.
	// The completed text is re-run through the unchanged strict scan —
	// all its ambiguity and schema rules still apply — and accepted only
	// on VALID.
	last := regions[len(regions)-1]
	if !last.closed && !last.inStringAtEnd && last.unclosed >= 1 && last.unclosed <= 2 &&
		!assessmentUnclosed(text, last) {
		completed := text + strings.Repeat("}", last.unclosed)
		if ans, ext := strictScan(completed); ans != nil {
			ext.Recovery = RecoveryBraceCompletion
			ext.Candidates[ext.SelectedIndex].Selector += fmt.Sprintf(
				"; recovered with %d appended '}'", last.unclosed)
			return ans, ext
		}
	}
	// Member salvage: recover the answer from the depth-1 `category` and
	// `reasoning` members of the object regions. Both must parse
	// completely and be non-empty, category must normalize into
	// validCategories, and across all regions exactly one distinct
	// (category, reasoning) pair may exist — divergent regions stay
	// ambiguous. assessment survives only when its own bytes are
	// parseable JSON.
	type salvagePair struct {
		category   string
		reasoning  string
		assessment json.RawMessage
		start      int
		end        int
	}
	var pairs []salvagePair
	for _, rg := range regions {
		m := salvageMembers(text, rg)
		cat, ok := m["category"]
		if !ok {
			continue
		}
		var catStr string
		if err := json.Unmarshal(cat, &catStr); err != nil {
			continue
		}
		catStr = strings.ToLower(catStr)
		if !validCategories[catStr] {
			continue
		}
		reas, ok := m["reasoning"]
		if !ok {
			continue
		}
		var reasStr string
		if err := json.Unmarshal(reas, &reasStr); err != nil {
			continue
		}
		if strings.TrimSpace(reasStr) == "" {
			continue
		}
		p := salvagePair{category: catStr, reasoning: reasStr, start: rg.start, end: rg.end}
		if v, ok := m["assessment"]; ok {
			p.assessment = v
		}
		dup := false
		for _, q := range pairs {
			if q.category == p.category && q.reasoning == p.reasoning {
				dup = true
				break
			}
		}
		if !dup {
			pairs = append(pairs, p)
		}
	}
	if len(pairs) != 1 {
		return nil, nil
	}
	p := pairs[0]
	raw, err := json.Marshal(map[string]any{
		"category":  p.category,
		"reasoning": p.reasoning,
		"assessment": func() json.RawMessage {
			if len(p.assessment) > 0 {
				return p.assessment
			}
			return nil
		}(),
	})
	if err != nil {
		return nil, nil
	}
	rs := sha256.Sum256(raw)
	ext := &Extraction{
		Status: ExtractionValid, InvalidReason: InvalidNone,
		CandidateCount: 1,
		Candidates: []ExtractionCandidate{{
			Index:           0,
			Status:          "VALID",
			Category:        strPtr(p.category),
			RawSHA256:       hex.EncodeToString(rs[:]),
			CanonicalSHA256: hex.EncodeToString(rs[:]),
			Selector: fmt.Sprintf(
				"members of bytes %d..%d of retained answer", p.start, p.end),
		}},
		SelectedIndex: 0,
		Recovery:      RecoveryMemberSalvage,
	}
	ans := &agentAnswer{
		Category:   p.category,
		Reasoning:  p.reasoning,
		Assessment: p.assessment,
	}
	return ans, ext
}

// jsonWS reports whether b is a JSON-insignificant whitespace byte.
func jsonWS(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// salvageMembers collects the depth-1 members of one object region whose
// values parse as complete JSON values. Member names are recognized only
// at object depth 1 (a name inside a nested object or array never
// counts). A member counts only when its value consumes the complete
// member bytes — decode must succeed and the next non-whitespace byte
// must be a member delimiter or the region end; a parseable prefix
// followed by stray bytes, or an undecodable value at all (including a
// string cut off mid-way), taints the member so it is absent from the
// result. An unterminated reasoning can never be salvaged by prefix, and
// assessment survives only on bytes that independently parse. Nothing is
// rewritten: member bytes are retained verbatim.
func salvageMembers(text string, rg objectRegion) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	tainted := map[string]bool{}
	depth := 1
	inStr, esc := false, false
	for i := rg.start + 1; i < rg.end; {
		c := text[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			i++
			continue
		}
		switch c {
		case '"':
			var raw json.RawMessage
			if err := json.NewDecoder(strings.NewReader(text[i:rg.end])).Decode(&raw); err != nil {
				// Not a complete string token — walk it as string
				// content so interior braces do not skew the depth.
				inStr = true
				i++
				continue
			}
			tokEnd := i + len(raw)
			var key string
			if json.Unmarshal(raw, &key) == nil && depth == 1 {
				j := tokEnd
				for j < rg.end && jsonWS(text[j]) {
					j++
				}
				if j < rg.end && text[j] == ':' {
					j++
					for j < rg.end && jsonWS(text[j]) {
						j++
					}
					tracked := key == "category" || key == "reasoning" || key == "assessment"
					var val json.RawMessage
					valOK := json.NewDecoder(strings.NewReader(text[j:rg.end])).Decode(&val) == nil
					if valOK {
						// The decoded value must consume the complete
						// member bytes: only whitespace may precede the
						// member delimiter or region end.
						k := j + len(val)
						for k < rg.end && jsonWS(text[k]) {
							k++
						}
						valOK = k == rg.end || text[k] == ',' || text[k] == '}' || text[k] == ']'
					}
					if tracked && valOK {
						if _, dup := out[key]; dup || tainted[key] {
							// A repeated depth-1 member is ambiguity
							// inside the region: JSON unmarshal would
							// silently last-win, but salvage must not
							// hide divergent statements.
							return nil
						}
						out[key] = val
					} else if tracked {
						tainted[key] = true
					}
					if valOK {
						i = j + len(val)
						continue
					}
				}
			}
			i = tokEnd
		case '{', '[':
			depth++
			i++
		case '}', ']':
			depth--
			i++
			if depth < 1 {
				return out
			}
		default:
			i++
		}
	}
	return out
}

// parseAgentAnswer is the legacy single-result view over strictExtract;
// kept for direct unit tests of the old scanning semantics.
func parseAgentAnswer(text string) (*agentAnswer, error) {
	ans, ext := strictExtract(text)
	if ans == nil {
		return nil, fmt.Errorf("answer extraction invalid (%s)", ext.InvalidReason)
	}
	return ans, nil
}
