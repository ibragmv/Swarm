package mcp

import (
	"encoding/json"
	"fmt"
)

// RegisterDefaultTools adds all autopentest tools to the MCP server.
func RegisterDefaultTools(s *Server) {
	s.RegisterTool(MCPTool{
		Name:        "scan_target",
		Description: "Start a full autonomous penetration test against a target",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string","description":"Target domain or IP"},"scope":{"type":"string","description":"Scope (CIDR or domain)"},"objective":{"type":"string","description":"What to find"}},"required":["target","scope"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				Target    string `json:"target"`
				Scope     string `json:"scope"`
				Objective string `json:"objective"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			return fmt.Sprintf("Campaign started for %s (scope: %s, objective: %s)", params.Target, params.Scope, params.Objective), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "quick_recon",
		Description: "Run reconnaissance only, return attack surface",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string","description":"Target to scan"}},"required":["target"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct{ Target string `json:"target"` }
			json.Unmarshal(args, &params)
			return fmt.Sprintf("Running recon on %s...", params.Target), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "check_vulnerability",
		Description: "Run nuclei with specific templates against a target",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"templates":{"type":"array","items":{"type":"string"}}},"required":["target"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				Target    string   `json:"target"`
				Templates []string `json:"templates"`
			}
			json.Unmarshal(args, &params)
			return fmt.Sprintf("Scanning %s with templates: %v", params.Target, params.Templates), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "explain_finding",
		Description: "Explain a vulnerability in plain English",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string"},"audience":{"type":"string","enum":["developer","manager","executive"]}},"required":["finding_id"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				FindingID string `json:"finding_id"`
				Audience  string `json:"audience"`
			}
			json.Unmarshal(args, &params)
			return fmt.Sprintf("Explaining finding %s for %s audience", params.FindingID, params.Audience), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "port_scan",
		Description: "Run a port scan against a target",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"ports":{"type":"string","description":"Port spec: top-100, top-1000, or specific ports"}},"required":["target"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				Target string `json:"target"`
				Ports  string `json:"ports"`
			}
			json.Unmarshal(args, &params)
			return fmt.Sprintf("Scanning ports on %s (%s)", params.Target, params.Ports), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "campaign_status",
		Description: "Get the current status of a campaign",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"campaign_id":{"type":"string"}},"required":["campaign_id"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct{ CampaignID string `json:"campaign_id"` }
			json.Unmarshal(args, &params)
			return fmt.Sprintf("Campaign %s: status not found", params.CampaignID), nil
		},
	})
}
