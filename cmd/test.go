package cmd

import (
	"fmt"

	"github.com/seaung/pocsuite-go/modules"
	"github.com/seaung/pocsuite-go/modules/manager"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test pocsuite-go modules",
	Long:  `Test various modules in pocsuite-go framework`,
	Run: func(cmd *cobra.Command, args []string) {
		testType, _ := cmd.Flags().GetString("type")

		switch testType {
		case "modules":
			testAllModules()
		case "search":
			testSearchModules()
		case "oast":
			testOASTModules()
		case "listener":
			testListenerModules()
		case "spider":
			testSpiderModules()
		default:
			fmt.Println("Running all tests...")
			testAllModules()
		}
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.Flags().String("type", "modules", "Test type: modules, search, oast, listener, spider")
}

func testAllModules() {
	fmt.Println("[*] Testing all modules...")
	fmt.Println()

	info := modules.GetModuleInfo()

	fmt.Println("[*] Available modules:")
	fmt.Printf("  Searchers: %v\n", info["searchers"])
	fmt.Printf("  OAST Services: %v\n", info["oast_services"])
	fmt.Printf("  Vulnerability DBs: %v\n", info["vuln_dbs"])
	fmt.Printf("  HTTP Servers: %v\n", info["http_servers"])
	fmt.Printf("  Listeners: %v\n", info["listeners"])
	fmt.Printf("  Spiders: %v\n", info["spiders"])
	fmt.Println()

	testSearchModules()
	testOASTModules()
	testListenerModules()
	testSpiderModules()
}

func testSearchModules() {
	fmt.Println("[*] Testing search modules...")

	searchers := []string{"shodan", "zoomeye", "censys", "fofa", "hunter", "quake"}

	for _, name := range searchers {
		fmt.Printf("\n[*] Testing %s module...\n", name)

		module, exists := manager.GetModuleManager().GetSearcher(name)
		if !exists {
			fmt.Printf("[-] Module %s not found\n", name)
			continue
		}

		fmt.Printf("[+] Module name: %s\n", module.Name())

		if err := module.Init(); err != nil {
			fmt.Printf("[-] Failed to initialize: %v\n", err)
			continue
		}

		if !module.IsAvailable() {
			fmt.Printf("[-] Module is not available (missing credentials?)\n")
			continue
		}

		fmt.Printf("[+] Module is available and initialized\n")
	}
}

func testOASTModules() {
	fmt.Println("\n[*] Testing OAST service modules...")

	oastServices := []string{"interactsh", "ceye"}

	for _, name := range oastServices {
		fmt.Printf("\n[*] Testing %s module...\n", name)

		module, exists := manager.GetModuleManager().GetOASTService(name)
		if !exists {
			fmt.Printf("[-] Module %s not found\n", name)
			continue
		}

		fmt.Printf("[+] Module name: %s\n", module.Name())

		if err := module.Init(); err != nil {
			fmt.Printf("[-] Failed to initialize: %v\n", err)
			continue
		}

		if !module.IsAvailable() {
			fmt.Printf("[-] Module is not available (missing credentials?)\n")
			continue
		}

		fmt.Printf("[+] Module is available and initialized\n")
		fmt.Printf("[+] OAST Domain: %s\n", module.GetDomain())
		fmt.Printf("[+] OAST URL: %s\n", module.GetURL())
	}
}

func testListenerModules() {
	fmt.Println("\n[*] Testing listener modules...")

	listeners := []string{"bind_tcp", "reverse_tcp"}

	for _, name := range listeners {
		fmt.Printf("\n[*] Testing %s module...\n", name)

		module, exists := manager.GetModuleManager().GetListener(name)
		if !exists {
			fmt.Printf("[-] Module %s not found\n", name)
			continue
		}

		fmt.Printf("[+] Module name: %s\n", module.Name())

		if err := module.Init(); err != nil {
			fmt.Printf("[-] Failed to initialize: %v\n", err)
			continue
		}

		if !module.IsAvailable() {
			fmt.Printf("[-] Module is not available\n")
			continue
		}

		fmt.Printf("[+] Module is available and initialized\n")
		fmt.Printf("[+] Note: To test listener, use --host and --port flags\n")
	}
}

func testSpiderModules() {
	fmt.Println("\n[*] Testing spider modules...")

	module, exists := manager.GetModuleManager().GetSpider("spider")
	if !exists {
		fmt.Printf("[-] Spider module not found\n")
		return
	}

	fmt.Printf("[+] Module name: %s\n", module.Name())

	if err := module.Init(); err != nil {
		fmt.Printf("[-] Failed to initialize: %v\n", err)
		return
	}

	if !module.IsAvailable() {
		fmt.Printf("[-] Module is not available\n")
		return
	}

	fmt.Printf("[+] Module is available and initialized\n")
	fmt.Printf("[+] Note: To test spider, provide a URL with --url flag\n")
}
