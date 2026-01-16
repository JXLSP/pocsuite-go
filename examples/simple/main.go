package main

import (
	"fmt"
	"log"

	"github.com/seaung/pocsuite-go/yamlpoc"
)

func main() {
	yamlContent := `
id: example-poc
info:
  name: Example POC
  author: knownsec
  severity: high
  description: This is an example POC

requests:
  - method: GET
    path: "/"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Example Domain"
`

	poc, err := yamlpoc.Parse(yamlContent)
	if err != nil {
		log.Fatalf("Failed to parse POC: %v", err)
	}

	fmt.Printf("POC Name: %s\n", poc.Info.Name)
	fmt.Printf("Author: %s\n", poc.Info.Author)
	fmt.Printf("Severity: %s\n", poc.Info.Severity)
	fmt.Printf("Description: %s\n", poc.Info.Description)
	fmt.Printf("Number of requests: %d\n", len(poc.Requests))

	target := "http://example.com"
	variables := map[string]interface{}{
		"custom_var": "value",
	}

	matched, extractedData, err := poc.Execute(target, variables)
	if err != nil {
		log.Fatalf("Failed to execute POC: %v", err)
	}

	if matched {
		fmt.Printf("\n[+] Target %s is vulnerable!\n", target)
		if len(extractedData) > 0 {
			fmt.Printf("[+] Extracted data: %v\n", extractedData)
		}
	} else {
		fmt.Printf("\n[-] Target %s is not vulnerable\n", target)
	}
}
