package evidencetools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Client is the typed-call adapter over a Session's in-memory MCP
// server: the smallest public surface that lets the research
// controller — deterministic lane first, then the bounded
// verification phase — invoke session tools through the same audited
// Observation contract an external agent would see. There is no
// unconfined call path: every Call crosses the MCP boundary, so
// handler dispatch, the confinement gate, the per-tool timeout and
// the session audit record are identical for every caller.
type Client struct {
	server *mcp.ServerSession
	client *mcp.ClientSession
}

// Connect wires an in-memory transport pair between s's MCP server
// and a controller client. The caller owns the returned client: Close
// releases both endpoints and must be called exactly once.
func (s *Session) Connect(ctx context.Context) (*Client, error) {
	st, ct := mcp.NewInMemoryTransports()
	srv := s.NewServer()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		return nil, fmt.Errorf("session server connect: %w", err)
	}
	mc := mcp.NewClient(&mcp.Implementation{Name: "research-controller", Version: "0"}, nil)
	cs, err := mc.Connect(ctx, ct, nil)
	if err != nil {
		_ = ss.Close()
		return nil, fmt.Errorf("session client connect: %w", err)
	}
	return &Client{server: ss, client: cs}, nil
}

// Call invokes one session tool and decodes the returned Observation.
// args is the request's raw argument object, passed to the tool
// verbatim (empty decodes as the tool's zero-argument shape). A nil
// Observation with non-nil error means no observation exists —
// transport failure, a protocol-level rejection (unknown tool,
// argument shape the schema cannot decode) or an undecodable result —
// so the caller must record the failed check itself instead of
// treating the call as absent.
func (c *Client) Call(ctx context.Context, tool string, args json.RawMessage) (*Observation, error) {
	var a any
	if len(args) > 0 {
		a = args
	}
	res, err := c.client.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: a})
	if err != nil {
		return nil, fmt.Errorf("tool call failed at transport: %w", err)
	}
	if res.IsError {
		return nil, fmt.Errorf("tool call rejected: %s", callResultText(res))
	}
	if res.StructuredContent == nil {
		return nil, fmt.Errorf("tool call returned no structured observation")
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return nil, fmt.Errorf("tool call structured content: %w", err)
	}
	var o Observation
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("tool call observation decode: %w", err)
	}
	return &o, nil
}

// Close releases the client and server endpoints of the in-memory
// pair. Callers must invoke it exactly once per Connect.
func (c *Client) Close() error {
	err := c.client.Close()
	if serr := c.server.Close(); err == nil {
		err = serr
	}
	return err
}

// callResultText extracts the error detail a tool endpoint returned
// instead of structured content.
func callResultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	if len(parts) == 0 {
		return "no error detail"
	}
	return strings.Join(parts, "; ")
}
