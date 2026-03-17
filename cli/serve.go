package cli

import (
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/api"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server and web dashboard",
	Example: `  pentestswarm serve
  pentestswarm serve --port 9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")

		fmt.Printf("Starting pentestswarm server on :%d\n", port)
		fmt.Printf("Dashboard: http://localhost:%d\n", port)
		fmt.Printf("API:       http://localhost:%d/api/v1\n", port)
		fmt.Println()

		server := api.NewServer(port)
		return server.Start()
	},
}

func init() {
	serveCmd.Flags().Int("port", 8080, "server port")
	rootCmd.AddCommand(serveCmd)
}
