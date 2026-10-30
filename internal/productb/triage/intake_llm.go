package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/llm"
)

// ExtractIntakeProposal runs the schema-guided intake extraction: one chat
// call whose system prompt marks the record as untrusted data and pins the
// intake-proposal.v1 shape. The model only proposes candidates — the
// returned transcript preserves the verbatim data message and raw model
// response for audit, and every field still needs ValidateIntakeProposal
// before it can support anything downstream. The extractor itself performs
// no deterministic extraction and never fabricates fields.
func ExtractIntakeProposal(
	ctx context.Context,
	client ChatClient,
	raw RawIntake,
) (IntakeProposal, []llm.ChatMessage, error) {
	if len(raw.Raw) == 0 {
		return IntakeProposal{}, nil, fmt.Errorf("empty intake record")
	}
	if client == nil {
		return IntakeProposal{}, nil, fmt.Errorf("llm chat client is nil")
	}

	system := BuildIntakePrompt()
	messages := []llm.ChatMessage{{Role: "user", Content: BuildIntakeDataMessage(raw)}}
	msg, finish, err := chatWithTransientRetry(ctx, nil, client, llm.Build, system, messages, nil)
	if err != nil {
		return IntakeProposal{}, nil, fmt.Errorf("intake extraction: %w", err)
	}
	transcript := append(messages, msg)

	if llm.IsRefusal(msg.Content, finish) {
		return IntakeProposal{}, transcript, fmt.Errorf("intake extraction refused: %s", llm.DescribeBadOutput(msg.Content, finish))
	}
	clean := extractJSON(msg.Content)
	if clean == "" {
		return IntakeProposal{}, transcript, fmt.Errorf("intake extraction produced %s", llm.DescribeBadOutput(msg.Content, finish))
	}
	var proposal IntakeProposal
	if err := json.Unmarshal([]byte(clean), &proposal); err != nil {
		return IntakeProposal{}, transcript, fmt.Errorf("decode intake proposal: %w", err)
	}
	if sv := strings.TrimSpace(proposal.SchemaVersion); sv != "" && sv != IntakeProposalSchemaVersion {
		return IntakeProposal{}, transcript, fmt.Errorf("unexpected schema_version %q, want %q", sv, IntakeProposalSchemaVersion)
	}
	proposal.SchemaVersion = IntakeProposalSchemaVersion
	proposal = normalizeIntakeProposal(proposal)
	if len(proposal.VulnerabilityIDs) > 0 {
		// Canonical IDs belong in vulnerability_ids; aliases are retained as
		// extracted references and validated independently.
		proposal.VulnerabilityIDs = append([]string(nil), proposal.VulnerabilityIDs...)
	}
	return proposal, transcript, nil
}
