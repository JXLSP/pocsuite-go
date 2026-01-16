package yamlpoc

import (
	"fmt"
	"os"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/seaung/pocsuite-go/request"
	"gopkg.in/yaml.v3"
)

type YAMLPOC struct {
	Info      Info              `yaml:"info"`
	Requests  []Request         `yaml:"requests"`
	Variables map[string]string `yaml:"variables,omitempty"`
}

type Info struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Author      string   `yaml:"author"`
	Reference   []string `yaml:"reference,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Remediation string   `yaml:"remediation,omitempty"`
}

type Request struct {
	Method     string            `yaml:"method"`
	Path       string            `yaml:"path"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string            `yaml:"body,omitempty"`
	Matchers   []Matcher         `yaml:"matchers,omitempty"`
	Extractors []Extractor       `yaml:"extractors,omitempty"`
	Condition  string            `yaml:"condition,omitempty"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Condition string   `yaml:"condition"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Regexes   []string `yaml:"regexes,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Size      []int    `yaml:"size,omitempty"`
	Binary    []string `yaml:"binary,omitempty"`
	Negative  bool     `yaml:"negative,omitempty"`
}

type Extractor struct {
	Type     string   `yaml:"type"`
	Name     string   `yaml:"name,omitempty"`
	Part     string   `yaml:"part"`
	Regex    []string `yaml:"regex,omitempty"`
	Kval     []string `yaml:"kval,omitempty"`
	JSON     []string `yaml:"json,omitempty"`
	XPath    []string `yaml:"xpath,omitempty"`
	Internal bool     `yaml:"internal,omitempty"`
}

func Parse(yamlContent string) (*YAMLPOC, error) {
	var poc YAMLPOC

	decoder := yaml.NewDecoder(strings.NewReader(yamlContent))
	if err := decoder.Decode(&poc); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &poc, nil
}

func ParseFile(yamlFile string) (*YAMLPOC, error) {
	var poc YAMLPOC

	data, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &poc, nil
}

func (poc *YAMLPOC) Execute(target string, variables map[string]interface{}) (bool, map[string]interface{}, error) {
	env := make(map[string]interface{})
	for k, v := range variables {
		env[k] = v
	}

	for k, v := range poc.Variables {
		env[k] = v
	}

	env["target"] = target

	allMatched := true
	extractedData := make(map[string]interface{})

	for i, req := range poc.Requests {
		evaluatedReq, err := poc.evaluateRequest(req, env)
		if err != nil {
			return false, nil, fmt.Errorf("failed to evaluate request %d: %w", i, err)
		}

		response, err := poc.executeRequest(target, evaluatedReq)
		if err != nil {
			return false, nil, fmt.Errorf("failed to execute request %d: %w", i, err)
		}

		env["response"] = response
		env["status_code"] = response.StatusCode
		env["body"] = response.BodyText
		env["headers"] = response.Headers

		matched, err := poc.checkMatchers(evaluatedReq.Matchers, response, env)
		if err != nil {
			return false, nil, fmt.Errorf("failed to check matchers for request %d: %w", i, err)
		}

		if !matched {
			allMatched = false
			break
		}

		extracted, err := poc.extractData(evaluatedReq.Extractors, response, env)
		if err != nil {
			return false, nil, fmt.Errorf("failed to extract data for request %d: %w", i, err)
		}

		for k, v := range extracted {
			extractedData[k] = v
			env[k] = v
		}
	}

	return allMatched, extractedData, nil
}

func (poc *YAMLPOC) evaluateRequest(req Request, env map[string]interface{}) (*Request, error) {
	evaluatedReq := req

	if strings.Contains(evaluatedReq.Path, "{{") {
		path, err := evalStringWithExpressions(evaluatedReq.Path, env)
		if err != nil {
			return nil, err
		}
		evaluatedReq.Path = path
	}

	for k, v := range evaluatedReq.Headers {
		if strings.Contains(v, "{{") {
			val, err := evalStringWithExpressions(v, env)
			if err != nil {
				return nil, err
			}
			evaluatedReq.Headers[k] = val
		}
	}

	if evaluatedReq.Body != "" && strings.Contains(evaluatedReq.Body, "{{") {
		body, err := evalStringWithExpressions(evaluatedReq.Body, env)
		if err != nil {
			return nil, err
		}
		evaluatedReq.Body = body
	}

	return &evaluatedReq, nil
}

func evalStringWithExpressions(str string, env map[string]interface{}) (string, error) {
	result := str
	start := 0

	for {
		openIdx := strings.Index(result[start:], "{{")
		if openIdx == -1 {
			break
		}
		openIdx += start

		closeIdx := strings.Index(result[openIdx:], "}}")
		if closeIdx == -1 {
			break
		}
		closeIdx += openIdx + 2

		exprStr := strings.TrimSpace(result[openIdx+2 : closeIdx-2])

		value, err := expr.Eval(exprStr, env)
		if err != nil {
			return "", fmt.Errorf("failed to evaluate expression '%s': %w", exprStr, err)
		}

		result = result[:openIdx] + fmt.Sprintf("%v", value) + result[closeIdx:]
		start = openIdx + len(fmt.Sprintf("%v", value))
	}

	return result, nil
}

func evalExpression(exprStr string, env map[string]interface{}) (interface{}, error) {
	exprStr = strings.TrimSpace(exprStr)
	if strings.HasPrefix(exprStr, "{{") && strings.HasSuffix(exprStr, "}}") {
		exprStr = strings.TrimSpace(exprStr[2 : len(exprStr)-2])
	}

	result, err := expr.Eval(exprStr, env)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate expression '%s': %w", exprStr, err)
	}

	return result, nil
}

func (poc *YAMLPOC) executeRequest(target string, req *Request) (*request.Response, error) {
	url := target + req.Path

	client := request.NewClient(nil)

	if req.Headers != nil {
		client.SetHeaders(req.Headers)
	}

	var response *request.Response
	var err error

	switch strings.ToUpper(req.Method) {
	case "GET":
		response, err = client.Get(url)
	case "POST":
		response, err = client.Post(url, req.Body)
	case "PUT":
		response, err = client.Put(url, req.Body)
	case "DELETE":
		response, err = client.Delete(url)
	default:
		return nil, fmt.Errorf("unsupported method: %s", req.Method)
	}

	if err != nil {
		return nil, err
	}

	return response, nil
}

func (poc *YAMLPOC) checkMatchers(matchers []Matcher, response *request.Response, env map[string]interface{}) (bool, error) {
	if len(matchers) == 0 {
		return true, nil
	}

	for _, matcher := range matchers {
		matched, err := poc.checkMatcher(matcher, response, env)
		if err != nil {
			return false, err
		}

		if matcher.Negative {
			matched = !matched
		}

		if !matched {
			return false, nil
		}
	}

	return true, nil
}

func (poc *YAMLPOC) checkMatcher(matcher Matcher, response *request.Response, env map[string]interface{}) (bool, error) {
	switch matcher.Type {
	case "status":
		return poc.checkStatusMatcher(matcher, response)
	case "word":
		return poc.checkWordMatcher(matcher, response)
	case "regex":
		return poc.checkRegexMatcher(matcher, response)
	case "size":
		return poc.checkSizeMatcher(matcher, response)
	default:
		return false, fmt.Errorf("unsupported matcher type: %s", matcher.Type)
	}
}

func (poc *YAMLPOC) checkStatusMatcher(matcher Matcher, response *request.Response) (bool, error) {
	for _, status := range matcher.Status {
		if response.StatusCode == status {
			return true, nil
		}
	}
	return false, nil
}

func (poc *YAMLPOC) checkWordMatcher(matcher Matcher, response *request.Response) (bool, error) {
	var content string

	switch matcher.Part {
	case "body", "":
		content = response.BodyText
	case "header":
		for _, word := range matcher.Words {
			for _, headerValue := range response.Headers {
				if strings.Contains(headerValue, word) {
					return true, nil
				}
			}
		}
		return false, nil
	case "all":
		content = response.BodyText
		for _, headerValue := range response.Headers {
			content += headerValue
		}
	default:
		return false, fmt.Errorf("unsupported part: %s", matcher.Part)
	}

	for _, word := range matcher.Words {
		if strings.Contains(content, word) {
			return true, nil
		}
	}

	return false, nil
}

func (poc *YAMLPOC) checkRegexMatcher(matcher Matcher, response *request.Response) (bool, error) {
	return false, nil
}

func (poc *YAMLPOC) checkSizeMatcher(matcher Matcher, response *request.Response) (bool, error) {
	size := len(response.BodyText)
	for _, s := range matcher.Size {
		if size == s {
			return true, nil
		}
	}
	return false, nil
}

func (poc *YAMLPOC) extractData(extractors []Extractor, response *request.Response, env map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, extractor := range extractors {
		extracted, err := poc.extractDataFromExtractor(extractor, response, env)
		if err != nil {
			return nil, err
		}

		if extractor.Name != "" {
			result[extractor.Name] = extracted
		}
	}

	return result, nil
}

func (poc *YAMLPOC) extractDataFromExtractor(extractor Extractor, response *request.Response, env map[string]interface{}) (interface{}, error) {
	switch extractor.Type {
	case "regex":
		return poc.extractRegex(extractor, response)
	case "kval":
		return poc.extractKval(extractor, response)
	case "json":
		return poc.extractJSON(extractor, response)
	default:
		return nil, fmt.Errorf("unsupported extractor type: %s", extractor.Type)
	}
}

func (poc *YAMLPOC) extractRegex(extractor Extractor, response *request.Response) (interface{}, error) {
	return nil, nil
}

func (poc *YAMLPOC) extractKval(extractor Extractor, response *request.Response) (interface{}, error) {
	result := make(map[string]string)

	for _, key := range extractor.Kval {
		if value, ok := response.Headers[key]; ok {
			result[key] = value
		}
	}

	return result, nil
}

func (poc *YAMLPOC) extractJSON(extractor Extractor, response *request.Response) (interface{}, error) {
	return nil, nil
}
