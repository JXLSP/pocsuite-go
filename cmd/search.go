package cmd

import (
	"fmt"
	"os"

	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/lib/core"
	"github.com/spf13/cobra"
)

var (
	searchDork   string
	searchPages  int
	searchModule string
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search using various search engines",
	Long:  `Search for targets using Shodan, ZoomEye, Censys, Fofa, Hunter, or Quake`,
	Run: func(cmd *cobra.Command, args []string) {
		if searchDork == "" {
			fmt.Println("Error: --dork is required")
			cmd.Help()
			os.Exit(1)
		}

		if searchModule == "" {
			fmt.Println("Error: --module is required")
			fmt.Println("Available modules: shodan, zoomeye, censys, fofa, hunter, quake")
			cmd.Help()
			os.Exit(1)
		}

		cfg, err := config.NewConfig(config.GetDefaultConfigPath())
		if err != nil {
			fmt.Printf("Error: Failed to create config: %v\n", err)
			os.Exit(1)
		}

		controller, err := core.NewController(cfg)
		if err != nil {
			fmt.Printf("Error: Failed to create controller: %v\n", err)
			os.Exit(1)
		}

		if err := controller.Initialize(); err != nil {
			fmt.Printf("Warning: Failed to initialize controller: %v\n", err)
		}

		fmt.Printf("[*] Searching with %s...\n", searchModule)
		fmt.Printf("[*] Dork: %s\n", searchDork)
		fmt.Printf("[*] Pages: %d\n", searchPages)
		fmt.Println()

		results, err := controller.SearchTargets(searchModule, searchDork)
		if err != nil {
			fmt.Printf("Error: Search failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Found %d results:\n", len(results))
		for i, result := range results {
			fmt.Printf("%d. %s\n", i+1, result)
		}

		if err := controller.Shutdown(); err != nil {
			fmt.Printf("Warning: Failed to shutdown controller: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().StringVarP(&searchDork, "dork", "d", "", "Search query/dork")
	searchCmd.Flags().StringVarP(&searchModule, "module", "m", "", "Search module: shodan, zoomeye, censys, fofa, hunter, quake")
	searchCmd.Flags().IntVarP(&searchPages, "pages", "p", 1, "Number of pages to search")
}
