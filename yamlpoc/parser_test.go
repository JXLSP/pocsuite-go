package yamlpoc

import (
	"testing"
)

func TestParse(t *testing.T) {
	yamlContent := `
id: test-poc
info:
  name: Test POC
  author: test
  severity: high
  description: Test description
requests:
  - method: GET
    path: "/test"
    matchers:
      - type: status
        status:
          - 200
`
	
	poc, err := Parse(yamlContent)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}
	
	if poc.Info.Name != "Test POC" {
		t.Errorf("Expected name 'Test POC', got '%s'", poc.Info.Name)
	}
	
	if poc.Info.Severity != "high" {
		t.Errorf("Expected severity 'high', got '%s'", poc.Info.Severity)
	}
	
	if len(poc.Requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(poc.Requests))
	}
	
	if poc.Requests[0].Method != "GET" {
		t.Errorf("Expected method 'GET', got '%s'", poc.Requests[0].Method)
	}
}

func TestEvalExpression(t *testing.T) {
	env := map[string]interface{}{
		"target": "http://example.com",
		"port":   8080,
		"host":   "example.com",
	}
	
	tests := []struct {
		name     string
		expr     string
		expected interface{}
	}{
		{
			name:     "simple variable",
			expr:     "target",
			expected: "http://example.com",
		},
		{
			name:     "number variable",
			expr:     "port",
			expected: 8080,
		},
		{
			name:     "string concatenation",
			expr:     "target + ':' + host",
			expected: "http://example.com:example.com",
		},
		{
			name:     "arithmetic",
			expr:     "port + 1",
			expected: 8081,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evalExpression(tt.expr, env)
			if err != nil {
				t.Fatalf("Failed to evaluate expression: %v", err)
			}
			
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
