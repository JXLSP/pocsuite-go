package cmd

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/lib/core"
	"github.com/seaung/pocsuite-go/modules"
	"github.com/spf13/cobra"
)

var (
	target      string
	pocFile     string
	pocDir      string
	verbose     bool
	mode        string
	optionsFile string
	consoleMode bool
)

var rootCmd = &cobra.Command{
	Use:   "pocsuite-go",
	Short: "pocsuite-go is a vulnerability detection framework",
	Long: `pocsuite-go is a Go-based vulnerability detection framework developed by Knownsec 404 Team.
It supports YAML-based POCs and uses the expr library for expression evaluation.`,
	Run: func(cmd *cobra.Command, args []string) {
		if consoleMode {
			runConsoleMode()
			return
		}

		if target == "" {
			fmt.Println("Error: target is required")
			cmd.Help()
			os.Exit(1)
		}

		if pocFile == "" && pocDir == "" {
			fmt.Println("Error: either --poc or --poc-dir is required")
			cmd.Help()
			os.Exit(1)
		}

		if pocFile != "" {
			if err := loadAndExecutePOC(pocFile, target); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		}

		if pocDir != "" {
			if err := loadAndExecutePOCsFromDir(pocDir, target); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target URL to test")
	rootCmd.PersistentFlags().StringVarP(&pocFile, "poc", "p", "", "POC file to execute")
	rootCmd.PersistentFlags().StringVarP(&pocDir, "poc-dir", "d", "", "Directory containing POC files")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "verify", "Execution mode: verify, attack, shell")
	rootCmd.PersistentFlags().StringVar(&optionsFile, "options", "", "Options file")
	rootCmd.PersistentFlags().BoolVar(&consoleMode, "console", false, "Run in interactive console mode")
}

func runConsoleMode() {
	fmt.Println("Starting pocsuite-go in console mode...")

	if err := modules.InitModules(); err != nil {
		fmt.Printf("Error: Failed to initialize modules: %v\n", err)
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

	console := core.NewConsole(controller)
	if err := console.Start(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if err := controller.Shutdown(); err != nil {
		fmt.Printf("Warning: Failed to shutdown controller: %v\n", err)
	}
}

func loadAndExecutePOC(pocPath, target string) error {
	if verbose {
		fmt.Printf("[*] Loading POC from: %s\n", pocPath)
	}

	if err := modules.InitModules(); err != nil {
		return fmt.Errorf("failed to initialize modules: %w", err)
	}

	cfg, err := config.NewConfig(config.GetDefaultConfigPath())
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	controller, err := core.NewController(cfg)
	if err != nil {
		return fmt.Errorf("failed to create controller: %w", err)
	}

	if err := controller.Initialize(); err != nil {
		fmt.Printf("Warning: Failed to initialize controller: %v\n", err)
	}

	pocName, err := controller.LoadPOC(pocPath)
	if err != nil {
		return fmt.Errorf("failed to load POC: %w", err)
	}

	if verbose {
		fmt.Printf("[*] POC loaded: %s\n", pocName)
	}

	if verbose {
		fmt.Printf("[*] Executing POC against target: %s\n", target)
		fmt.Printf("[*] Mode: %s\n", mode)
	}

	output, err := controller.ExecutePOC(pocName, target, mode)
	if err != nil {
		return fmt.Errorf("POC execution failed: %w", err)
	}

	fmt.Println(output.String())

	if err := controller.Shutdown(); err != nil {
		fmt.Printf("Warning: Failed to shutdown controller: %v\n", err)
	}

	return nil
}

func loadAndExecutePOCsFromDir(dir, target string) error {
	if verbose {
		fmt.Printf("[*] Loading POCs from directory: %s\n", dir)
	}

	if err := modules.InitModules(); err != nil {
		return fmt.Errorf("failed to initialize modules: %w", err)
	}

	cfg, err := config.NewConfig(config.GetDefaultConfigPath())
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	controller, err := core.NewController(cfg)
	if err != nil {
		return fmt.Errorf("failed to create controller: %w", err)
	}

	if err := controller.Initialize(); err != nil {
		fmt.Printf("Warning: Failed to initialize controller: %v\n", err)
	}

	loadedPOCs, err := controller.LoadPOCsFromDir(dir)
	if err != nil {
		return fmt.Errorf("failed to load POCs from directory: %w", err)
	}

	if len(loadedPOCs) == 0 {
		return fmt.Errorf("no POCs loaded from directory")
	}

	if verbose {
		fmt.Printf("[*] Loaded %d POCs\n", len(loadedPOCs))
	}

	successCount := 0
	for _, pocName := range loadedPOCs {
		fmt.Printf("\n[*] Processing: %s\n", pocName)

		output, err := controller.ExecutePOC(pocName, target, mode)
		if err != nil {
			fmt.Printf("[-] Error: %v\n", err)
			continue
		}

		fmt.Println(output.String())
		successCount++
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithMaxWidth(80),
		tablewriter.WithColumnMax(30),
	)
	table.Header("Metric", "Value")

	var rows [][]any
	rows = append(rows, []any{"Total POCs", fmt.Sprintf("%d", len(loadedPOCs))})
	rows = append(rows, []any{"Successful", fmt.Sprintf("%d", successCount)})
	rows = append(rows, []any{"Failed", fmt.Sprintf("%d", len(loadedPOCs)-successCount)})
	rows = append(rows, []any{"Success Rate", fmt.Sprintf("%.1f%%", float64(successCount)/float64(len(loadedPOCs))*100)})
	table.Bulk(rows)

	fmt.Printf("\n[*] Execution Summary:\n")
	table.Render()

	if err := controller.Shutdown(); err != nil {
		fmt.Printf("Warning: Failed to shutdown controller: %v\n", err)
	}

	return nil
}
