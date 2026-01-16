package main

import (
	"fmt"
	"log"

	"github.com/seaung/pocsuite-go/yamlpoc"
)

func main() {
	yamlContent := `
id: advanced-example
info:
  name: Advanced POC Example
  author: knownsec
  severity: critical
  description: Demonstrates advanced features like expressions and multiple requests

variables:
  username: admin
  password: password123

requests:
  - method: GET
    path: "/login"
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: kval
        name: csrf_token
        kval:
          - X-CSRF-Token

  - method: POST
    path: "/login"
    headers:
      Content-Type: "application/json"
      X-CSRF-Token: "{{csrf_token}}"
    body: '{"username": "{{username}}", "password": "{{password}}"}'
    matchers:
      - type: status
        status:
          - 200
          - 302
      - type: word
        part: body
        words:
          - "Welcome"
          - "Dashboard"
        condition: or
`

	poc, err := yamlpoc.Parse(yamlContent)
	if err != nil {
		log.Fatalf("Failed to parse POC: %v", err)
	}

	fmt.Printf("=== Advanced POC Example ===\n")
	fmt.Printf("POC Name: %s\n", poc.Info.Name)
	fmt.Printf("Severity: %s\n", poc.Info.Severity)
	fmt.Printf("\nVariables:\n")
	for k, v := range poc.Variables {
		fmt.Printf("  %s: %s\n", k, v)
	}

	fmt.Printf("\nRequests:\n")
	for i, req := range poc.Requests {
		fmt.Printf("  Request %d:\n", i+1)
		fmt.Printf("    Method: %s\n", req.Method)
		fmt.Printf("    Path: %s\n", req.Path)
		fmt.Printf("    Matchers: %d\n", len(req.Matchers))
		fmt.Printf("    Extractors: %d\n", len(req.Extractors))
	}

	target := "http://example.com"
	variables := map[string]interface{}{
		"custom_var": "custom_value",
	}

	fmt.Printf("\n=== Executing POC ===\n")
	fmt.Printf("Target: %s\n", target)

	matched, extractedData, err := poc.Execute(target, variables)
	if err != nil {
		log.Printf("Failed to execute POC: %v", err)
		return
	}

	if matched {
		fmt.Printf("\n[+] Target %s is vulnerable!\n", target)
		if len(extractedData) > 0 {
			fmt.Printf("\n[+] Extracted Data:\n")
			for k, v := range extractedData {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	} else {
		fmt.Printf("\n[-] Target %s is not vulnerable\n", target)
	}
}
