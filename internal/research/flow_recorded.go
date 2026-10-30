package research

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// flowWirePlan is the closed recorded plan contract. Both historical check_id
// and adapter_id name the same adapter slot; decoding confers no authority.
type flowWirePlan struct {
	StepID       string   `json:"step_id"`
	ConditionIDs []string `json:"condition_ids"`
	Actions      []struct {
		ID          string          `json:"id"`
		AdapterID   string          `json:"adapter_id"`
		CheckID     string          `json:"check_id"`
		Arguments   json.RawMessage `json:"arguments"`
		Purpose     string          `json:"purpose"`
		ConditionID string          `json:"condition_id"`
		Anchor      string          `json:"anchor"`
	} `json:"actions"`
}

// decodeLastJSON preserves the base decoder for recorded answers without
// restoring the production model driver.
func decodeLastJSON(text string, dst any) error {
	var last json.RawMessage
	for i := 0; i < len(text); i++ {
		if text[i] != '{' {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(text[i:]))
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			continue
		}
		i += int(dec.InputOffset()) - 1
		if len(v) > 0 && v[0] == '{' {
			last = v
		}
	}
	if len(last) == 0 {
		return errors.New("no JSON object in the answer")
	}
	dec := json.NewDecoder(bytes.NewReader(last))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("answer object does not satisfy the contract: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("answer object carries trailing content")
	}
	return nil
}
