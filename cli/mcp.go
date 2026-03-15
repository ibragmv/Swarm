package cli

import (
	"fmt"

	mcpserver "github.com/Armur-Ai/autopentest/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for Claude Desktop and Cursor integration",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start MCP server (stdio transport)",
	Long: `Starts an MCP server that exposes autopentest tools to Claude Desktop,
Cursor, and any MCP-compatible AI client.

Add to Claude Desktop config:
  {
    "mcpServers": {
      "autopentest": {
        "command": "autopentest",
        "args": ["mcp", "serve"]
      }
    }
  }`,
	RunE: func(cmd *cobra.Command, args []string) error {
		server := mcpserver.NewServer()
		mcpserver.RegisterDefaultTools(server)

		fmt.Fprintln(cmd.ErrOrStderr(), "autopentest MCP server started (stdio)")
		return server.Serve()
	},
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}
