package vexbench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/productb/triage"
)

// VexTriageRunSchemaVersion pins the execution run schema.
const VexTriageRunSchemaVersion = "vex-triage-run.v1"

// ModelPricing records version-pinned pricing per token.
type ModelPricing struct {
	VersionID          string  `json:"version_id"`
	PromptPerToken     float64 `json:"prompt_per_token"`
	CompletionPerToken float64 `json:"completion_per_token"`
}

// ModelPin pins the exact model configuration and observed identity.
type ModelPin struct {
	RequestedModel      string        `json:"requested_model"`
	ReturnedModel       string        `json:"returned_model,omitempty"`
	ProviderFingerprint string        `json:"provider_fingerprint,omitempty"`
	MutableAlias        bool          `json:"mutable_alias"`
	Pricing             *ModelPricing `json:"pricing,omitempty"`
}

// VexTriageRun pins the complete execution provenance and accounts for real model usage.
type VexTriageRun struct {
	SchemaVersion         string             `json:"schema_version"`
	FindingID             string             `json:"finding_id"`
	InputBundleHash       string             `json:"input_bundle_hash"`
	CodeCommit            string             `json:"code_commit"`
	Toolchain             string             `json:"toolchain"`
	ToolRegistryVersion   string             `json:"tool_registry_version"`
	PromptHash            string             `json:"prompt_hash"`
	PromptInput           triage.PromptInput `json:"prompt_input"`
	Model                 ModelPin           `json:"model"`
	ConfigHash            string             `json:"config_hash"`
	Authorized            bool               `json:"authorized"`
	Exchanges             []llm.ChatExchange `json:"exchanges"`
	TotalPromptTokens     *int64             `json:"total_prompt_tokens,omitempty"`
	TotalCompletionTokens *int64             `json:"total_completion_tokens,omitempty"`
	TotalTokens           *int64             `json:"total_tokens,omitempty"`
	CostUSD               *float64           `json:"cost_usd,omitempty"`
	CostStatus            string             `json:"cost_status"` // "assessed" | "unassessed"
	ArmResultRef          string             `json:"arm_result_ref,omitempty"`
	Error                 string             `json:"error,omitempty"`
	ExecutedAt            time.Time          `json:"executed_at"`
}

// Validate validates that required pins are present.
func (r VexTriageRun) Validate() error {
	if r.SchemaVersion != VexTriageRunSchemaVersion {
		return fmt.Errorf("unexpected schema version %q, want %q", r.SchemaVersion, VexTriageRunSchemaVersion)
	}
	if strings.TrimSpace(r.FindingID) == "" {
		return errors.New("vex-triage-run: finding_id is required")
	}
	if strings.TrimSpace(r.PromptHash) == "" {
		return errors.New("vex-triage-run: prompt_hash is required")
	}
	if strings.TrimSpace(r.ToolRegistryVersion) == "" {
		return errors.New("vex-triage-run: tool_registry_version is required")
	}
	if strings.TrimSpace(r.Model.RequestedModel) == "" {
		return errors.New("vex-triage-run: requested model is required")
	}
	return nil
}

// ComputeUsage sums up observed token counts and computes cost if pricing is pinned.
func (r *VexTriageRun) ComputeUsage() {
	var pTokens, cTokens, tTokens int64
	hasAnyUsage := false
	allAttemptsHaveUsage := len(r.Exchanges) > 0

	for _, ex := range r.Exchanges {
		if ex.HasUsage && ex.Usage != nil {
			hasAnyUsage = true
			if ex.Usage.PromptTokens != nil {
				pTokens += *ex.Usage.PromptTokens
			}
			if ex.Usage.CompletionTokens != nil {
				cTokens += *ex.Usage.CompletionTokens
			}
			if ex.Usage.TotalTokens != nil {
				tTokens += *ex.Usage.TotalTokens
			}
		} else {
			allAttemptsHaveUsage = false
		}
	}

	if hasAnyUsage && allAttemptsHaveUsage {
		r.TotalPromptTokens = &pTokens
		r.TotalCompletionTokens = &cTokens
		r.TotalTokens = &tTokens

		if r.Model.Pricing != nil && r.Model.Pricing.VersionID != "" {
			cost := float64(pTokens)*r.Model.Pricing.PromptPerToken + float64(cTokens)*r.Model.Pricing.CompletionPerToken
			r.CostUSD = &cost
			r.CostStatus = "assessed"
		} else {
			r.CostStatus = "unassessed"
		}
	} else {
		// Missing or partial usage means cost cannot be accurately computed
		r.CostStatus = "unassessed"
	}
}

// Save writes vex-triage-run.v1 atomically into target path.
func (r VexTriageRun) Save(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vex-triage-run: %w", err)
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write temp vex-triage-run: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename vex-triage-run: %w", err)
	}
	return nil
}

// HashInputBundle computes a stable sha256 hash over prepared case bytes.
func HashInputBundle(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}
