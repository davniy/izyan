package llm

import (
	"context"
	"fmt"
	"strings"
)

// translateSystemPrompt fixes the translation contract: faithful literal
// rendering, identifiers and code untouched, no added or dropped facts.
const translateSystemPrompt = "You translate English Go-vulnerability advisory text into Russian for a security report. Translate faithfully and literally. Keep Go identifiers, module paths, function names, CVE/GO/GHSA ids, and code fragments unchanged. Do not add, remove, summarize or interpret. Output only the translation, without quotes or commentary."

// Translator renders externally sourced English prose into Russian for the
// human report. Translation is a presentation transform only: it never adds,
// removes or interprets facts, and the original text stays authoritative.
type Translator struct {
	Client *Client
}

// ModelName reports the model used for translation, for Localization.Model.
func (t Translator) ModelName() string { return t.Client.modelFor(Analyze) }

// Translate renders text in Russian. The caller is responsible for usage
// accounting (AnalysisCase.IncLLMCalls) — translation may run in a state
// that owns the case, not here.
func (t Translator) Translate(ctx context.Context, text string) (string, error) {
	if t.Client == nil {
		return "", fmt.Errorf("llm client is nil")
	}
	content, finish, err := t.Client.Complete(ctx, Analyze, translateSystemPrompt, text)
	if err != nil {
		return "", err
	}
	if IsRefusal(content, finish) {
		return "", fmt.Errorf("llm refusal in translation: %s", DescribeBadOutput(content, finish))
	}
	out := stripSurroundingQuotes(strings.TrimSpace(content))
	if out == "" {
		return "", fmt.Errorf("empty translation: %s", DescribeBadOutput(content, finish))
	}
	return out, nil
}

// stripSurroundingQuotes removes a single pair of quotes models sometimes
// wrap the whole answer in despite the prompt.
func stripSurroundingQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	return s
}
