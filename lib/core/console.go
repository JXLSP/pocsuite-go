package core

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/seaung/pocsuite-go/registry"
)

type Console struct {
	controller *Controller
	scanner    *bufio.Scanner
	running    bool
}

func NewConsole(controller *Controller) *Console {
	return &Console{
		controller: controller,
		scanner:    bufio.NewScanner(os.Stdin),
		running:    true,
	}
}

func (c *Console) Start() error {
	c.printBanner()

	for c.running {
		prompt := c.getPrompt()
		fmt.Print(prompt)

		if !c.scanner.Scan() {
			break
		}

		line := strings.TrimSpace(c.scanner.Text())
		if line == "" {
			continue
		}

		if err := c.executeCommand(line); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	return nil
}

func (c *Console) printBanner() {
	banner := `
   ___      _          _____ _                  _____
  / _ \    | |        / ____| |                |  __ \
 | | | | __| | __ _  | |    | |__   ___ _ __  | |__) |_ _ _ __   ___ _ __
 | | | |/ _  |/ _  | | |    | '_ \ / _ \ '__| |  ___/ _  | '_ \ / _ \ '__|
 | |_| | (_| | (_| | | |____| | | |  __/ |    | |  | (_| | |_) |  __/ |
  \___/ \__,_|\__,_|  \_____|_| |_|\___|_|    |_|   \__,_| .__/ \___|_|
                                                           | |
                                                           |_|

pocsuite-go - Go-based vulnerability detection framework
Type 'help' for available commands
`
	fmt.Println(banner)
}

func (c *Console) getPrompt() string {
	return "pocsuite> "
}

func (c *Console) executeCommand(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help":
		c.cmdHelp(args)
	case "exit", "quit":
		c.cmdExit()
	case "search":
		return c.cmdSearch(args)
	case "list", "show":
		return c.cmdList(args)
	case "use":
		return c.cmdUse(args)
	case "set":
		return c.cmdSet(args)
	case "run":
		return c.cmdRun(args)
	case "check":
		return c.cmdCheck(args)
	case "attack":
		return c.cmdAttack(args)
	case "results":
		c.cmdResults()
	case "clear":
		c.cmdClear()
	case "load":
		return c.cmdLoad(args)
	case "unload":
		return c.cmdUnload(args)
	case "listener":
		return c.cmdListener(args)
	case "spider":
		return c.cmdSpider(args)
	case "httpserver":
		return c.cmdHTTPServer(args)
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}

	return nil
}

func (c *Console) cmdHelp(args []string) {
	help := `
Global commands:
  help                    Show this help message
  exit/quit               Exit the console
  search <query>          Search for POCs
  list/show all           List all available POCs
  use <poc>               Select a POC to use
  set <key> <value>       Set a global option
  load <file|dir>         Load POC from file or directory
  unload <poc>            Unload a POC
  show <pocs|options>     Show loaded POCs, options, or results
  run <target>            Run selected POC against target
  check <target>          Check if target is vulnerable
  attack <target>         Attack target
  results                 Show all results
  clear                   Clear the screen

Listener commands:
  listener start <name>   Start a listener (bind_tcp, reverse_tcp)
  listener stop <name>    Stop a listener
  listener list           List all listeners
  listener clients        List all connected clients
  listener send <id> <cmd> Send command to client
  listener read <id>      Read response from client

Spider commands:
  spider crawl <url> [depth]  Crawl a URL and discover links
  spider redirect <url>       Get redirect URL

HTTPServer commands:
  httpserver start [port]    Start HTTP server (default: 6666)
  httpserver stop            Stop HTTP server
  httpserver url             Get HTTP server URL
  httpserver ip              Get HTTP server host IP
`
	fmt.Println(help)
}

func (c *Console) cmdExit() {
	fmt.Println("Exiting pocsuite-go...")
	c.running = false
}

func (c *Console) cmdSearch(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("search query is required")
	}

	query := strings.Join(args, " ")
	pocs := registry.Search(query)

	if len(pocs) == 0 {
		fmt.Println("No POCs found")
		return nil
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithMaxWidth(80),
		tablewriter.WithColumnMax(30),
	)
	table.Header("#", "POC Name")

	var rows [][]any
	for i, poc := range pocs {
		rows = append(rows, []any{fmt.Sprintf("%d", i+1), poc})
	}
	table.Bulk(rows)

	fmt.Printf("Found %d POC(s):\n", len(pocs))
	table.Render()

	return nil
}

func (c *Console) cmdList(args []string) error {
	allPocs := registry.ListAll()

	if len(allPocs) == 0 {
		fmt.Println("No POCs available")
		return nil
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithMaxWidth(80),
		tablewriter.WithColumnMax(30),
	)
	table.Header("#", "POC Name")

	var rows [][]any
	for i, name := range allPocs {
		rows = append(rows, []any{fmt.Sprintf("%d", i+1), name})
	}
	table.Bulk(rows)

	fmt.Printf("Available POCs (%d):\n", len(allPocs))
	table.Render()

	return nil
}

func (c *Console) cmdUse(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("POC name is required")
	}

	pocName := args[0]
	if _, exists := registry.Get(pocName); !exists {
		return fmt.Errorf("POC '%s' not found", pocName)
	}

	c.controller.SetOption("current_poc", pocName)
	fmt.Printf("Selected POC: %s\n", pocName)

	return nil
}

func (c *Console) cmdSet(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: set <key> <value>")
	}

	key := args[0]
	value := strings.Join(args[1:], " ")
	c.controller.SetOption(key, value)
	fmt.Printf("Set %s = %s\n", key, value)

	return nil
}

func (c *Console) cmdRun(args []string) error {
	pocName, ok := c.controller.GetOption("current_poc")
	if !ok {
		return fmt.Errorf("no POC selected. Use 'use <poc>' first")
	}

	if len(args) == 0 {
		return fmt.Errorf("target is required")
	}

	target := args[0]
	mode := "verify"
	if len(args) > 1 {
		mode = args[1]
	}

	output, err := c.controller.ExecutePOC(pocName.(string), target, mode)
	if err != nil {
		return err
	}

	fmt.Println(output.String())
	return nil
}

func (c *Console) cmdCheck(args []string) error {
	pocName, ok := c.controller.GetOption("current_poc")
	if !ok {
		return fmt.Errorf("no POC selected. Use 'use <poc>' first")
	}

	if len(args) == 0 {
		return fmt.Errorf("target is required")
	}

	target := args[0]
	output, err := c.controller.ExecutePOC(pocName.(string), target, "verify")
	if err != nil {
		return err
	}

	fmt.Println(output.String())
	return nil
}

func (c *Console) cmdAttack(args []string) error {
	pocName, ok := c.controller.GetOption("current_poc")
	if !ok {
		return fmt.Errorf("no POC selected. Use 'use <poc>' first")
	}

	if len(args) == 0 {
		return fmt.Errorf("target is required")
	}

	target := args[0]
	output, err := c.controller.ExecutePOC(pocName.(string), target, "attack")
	if err != nil {
		return err
	}

	fmt.Println(output.String())
	return nil
}

func (c *Console) cmdResults() {
	results := c.controller.GetResults()

	if len(results) == 0 {
		fmt.Println("No results yet")
		return
	}

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithMaxWidth(120),
		tablewriter.WithColumnMax(50),
	)
	table.Header("#", "Status", "Message", "Data")

	var rows [][]any
	for i, result := range results {
		status := "✗"
		if result.Success {
			status = "✓"
		}

		dataStr := fmt.Sprintf("%v", result.Data)
		if len(dataStr) > 40 {
			dataStr = dataStr[:40] + "..."
		}

		rows = append(rows, []any{
			fmt.Sprintf("%d", i+1),
			status,
			result.Message,
			dataStr,
		})
	}
	table.Bulk(rows)

	fmt.Printf("Results (%d):\n", len(results))
	table.Render()
}

func (c *Console) cmdClear() {
	fmt.Print("\033[H\033[2J")
}

func (c *Console) cmdLoad(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: load <file|directory>")
	}

	path := args[0]

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if info.IsDir() {
		loaded, err := c.controller.LoadPOCsFromDir(path)
		if err != nil {
			return err
		}
		fmt.Printf("Loaded %d POC(s) from directory: %s\n", len(loaded), path)
	} else {
		pocName, err := c.controller.LoadPOC(path)
		if err != nil {
			return err
		}
		fmt.Printf("Loaded POC: %s from file: %s\n", pocName, path)
	}

	return nil
}

func (c *Console) cmdUnload(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: unload <poc_name>")
	}

	pocName := args[0]
	if err := c.controller.UnloadPOC(pocName); err != nil {
		return err
	}

	fmt.Printf("Unloaded POC: %s\n", pocName)
	return nil
}

func (c *Console) cmdShow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: show <pocs|options|results>")
	}

	what := strings.ToLower(args[0])

	switch what {
	case "pocs", "poc":
		pocs := c.controller.GetLoadedPOCs()
		if len(pocs) == 0 {
			fmt.Println("No POCs loaded")
			return nil
		}

		table := tablewriter.NewTable(os.Stdout,
			tablewriter.WithMaxWidth(80),
			tablewriter.WithColumnMax(30),
		)
		table.Header("#", "POC Name")

		var rows [][]any
		for i, poc := range pocs {
			rows = append(rows, []any{fmt.Sprintf("%d", i+1), poc})
		}
		table.Bulk(rows)

		fmt.Printf("Loaded POCs (%d):\n", len(pocs))
		table.Render()

	case "options", "option":
		if pocName, ok := c.controller.GetOption("current_poc"); ok {
			fmt.Printf("Current POC: %s\n", pocName)
		} else {
			fmt.Println("No POC selected")
		}

	case "results", "result":
		c.cmdResults()

	default:
		return fmt.Errorf("unknown show command: %s", what)
	}

	return nil
}

func (c *Console) cmdListener(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: listener <start|stop|list|clients|send|read> [args...]")
	}

	action := strings.ToLower(args[0])

	switch action {
	case "start":
		if len(args) < 2 {
			return fmt.Errorf("usage: listener start <reverse_tcp|bind_tcp> [port|address]")
		}

		listenerType := args[1]

		if listenerType == "reverse_tcp" {
			port := 4444
			if len(args) > 2 {
				if _, err := fmt.Sscanf(args[2], "%d", &port); err != nil {
					return fmt.Errorf("invalid port number: %w", err)
				}
				if port < 1 || port > 65535 {
					return fmt.Errorf("port number out of range: %d", port)
				}
			}
			c.controller.SetOption("reverse_tcp_port", fmt.Sprintf("%d", port))
			if err := c.controller.StartListener("reverse_tcp"); err != nil {
				return err
			}
			fmt.Printf("Reverse TCP listener started on port %d\n", port)
			return nil
		}

		if listenerType == "bind_tcp" {
			if len(args) < 3 {
				return fmt.Errorf("usage: listener start bind_tcp <host:port>")
			}
			address := args[2]
			c.controller.SetOption("bind_tcp_address", address)
			if err := c.controller.StartListener("bind_tcp"); err != nil {
				return err
			}
			fmt.Printf("Bind TCP listener connected to %s\n", address)
			return nil
		}

		name := args[1]
		if err := c.controller.StartListener(name); err != nil {
			return err
		}
		fmt.Printf("Listener '%s' started successfully\n", name)

	case "stop":
		if len(args) < 2 {
			return fmt.Errorf("usage: listener stop <name>")
		}
		name := args[1]
		if err := c.controller.StopListener(name); err != nil {
			return err
		}
		fmt.Printf("Listener '%s' stopped successfully\n", name)

	case "list":
		fmt.Println("Available listeners: bind_tcp, reverse_tcp")

	case "clients":
		clients := c.controller.ListClients()
		if len(clients) == 0 {
			fmt.Println("No connected clients")
			return nil
		}

		table := tablewriter.NewTable(os.Stdout,
			tablewriter.WithMaxWidth(80),
			tablewriter.WithColumnMax(30),
		)
		table.Header("#", "Address", "Connection")

		var rows [][]any
		for i, client := range clients {
			rows = append(rows, []any{
				fmt.Sprintf("%d", i+1),
				client.Address,
				fmt.Sprintf("%v", client.Conn),
			})
		}
		table.Bulk(rows)

		fmt.Printf("Connected clients (%d):\n", len(clients))
		table.Render()

	case "send":
		if len(args) < 3 {
			return fmt.Errorf("usage: listener send <client_id> <command>")
		}
		clientID := 0
		if _, err := fmt.Sscanf(args[1], "%d", &clientID); err != nil {
			return fmt.Errorf("invalid client ID: %w", err)
		}
		command := strings.Join(args[2:], " ")
		if err := c.controller.SendCommand(clientID, command); err != nil {
			return err
		}
		fmt.Printf("Command sent to client %d\n", clientID)

	case "read":
		if len(args) < 2 {
			return fmt.Errorf("usage: listener read <client_id>")
		}
		clientID := 0
		if _, err := fmt.Sscanf(args[1], "%d", &clientID); err != nil {
			return fmt.Errorf("invalid client ID: %w", err)
		}
		response, err := c.controller.ReadResponse(clientID, 5*time.Second)
		if err != nil {
			return err
		}
		fmt.Printf("Response from client %d: %s\n", clientID, response)

	default:
		return fmt.Errorf("unknown listener command: %s", action)
	}

	return nil
}

func (c *Console) cmdSpider(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: spider <crawl|redirect> [args...]")
	}

	action := strings.ToLower(args[0])

	switch action {
	case "crawl":
		if len(args) < 2 {
			return fmt.Errorf("usage: spider crawl <url> [depth]")
		}
		url := args[1]
		depth := 1
		if len(args) > 2 {
			if _, err := fmt.Sscanf(args[2], "%d", &depth); err != nil {
				return fmt.Errorf("invalid depth: %w", err)
			}
		}
		urls, err := c.controller.CrawlURL(url, depth)
		if err != nil {
			return err
		}
		fmt.Printf("Crawled %d URLs:\n", len(urls))
		for i, u := range urls {
			fmt.Printf("%d. %s\n", i+1, u)
		}

	case "redirect":
		if len(args) < 2 {
			return fmt.Errorf("usage: spider redirect <url>")
		}
		url := args[1]
		redirectURL, err := c.controller.GetRedirectURL(url)
		if err != nil {
			return err
		}
		fmt.Printf("Original URL: %s\n", url)
		fmt.Printf("Redirect URL: %s\n", redirectURL)

	default:
		return fmt.Errorf("unknown spider command: %s", action)
	}

	return nil
}

func (c *Console) cmdHTTPServer(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: httpserver <start|stop|url|ip> [args...]")
	}

	action := strings.ToLower(args[0])

	switch action {
	case "start":
		port := 6666
		if len(args) > 1 {
			if _, err := fmt.Sscanf(args[1], "%d", &port); err != nil {
				return fmt.Errorf("invalid port: %w", err)
			}
		}
		if err := c.controller.StartHTTPServer(port); err != nil {
			return err
		}
		fmt.Printf("HTTP server started on port %d\n", port)

	case "stop":
		if err := c.controller.StopHTTPServer(); err != nil {
			return err
		}
		fmt.Println("HTTP server stopped successfully")

	case "url":
		url := c.controller.GetHTTPServerURL()
		fmt.Printf("HTTP Server URL: %s\n", url)

	case "ip":
		ip := c.controller.GetHTTPServerHostIP()
		fmt.Printf("HTTP Server Host IP: %s\n", ip)

	default:
		return fmt.Errorf("unknown httpserver command: %s", action)
	}

	return nil
}
