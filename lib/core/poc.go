package core

import (
	"encoding/json"
	"fmt"
	"time"
)

type POC struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Author      string                 `json:"author"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	References  []string               `json:"references"`
	CVE         string                 `json:"cve"`
	CVSS        float64                `json:"cvss"`
	Options     map[string]interface{} `json:"options"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type POCResult struct {
	POCID      string                 `json:"poc_id"`
	Target     string                 `json:"target"`
	Status     string                 `json:"status"`
	Message    string                 `json:"message"`
	Data       map[string]interface{} `json:"data"`
	ExecutedAt time.Time              `json:"executed_at"`
	Duration   time.Duration          `json:"duration"`
}

type POCExecutor interface {
	Execute(poc *POC, target string) (*POCResult, error)
	Validate(poc *POC) error
	GetSupportedPOCs() []*POC
}

type POCManager struct {
	pocs      map[string]*POC
	executors map[string]POCExecutor
}

func NewPOCManager() *POCManager {
	return &POCManager{
		pocs:      make(map[string]*POC),
		executors: make(map[string]POCExecutor),
	}
}

func (pm *POCManager) AddPOC(poc *POC) error {
	if poc == nil {
		return fmt.Errorf("poc cannot be nil")
	}

	if poc.ID == "" {
		return fmt.Errorf("poc ID cannot be empty")
	}

	poc.CreatedAt = time.Now()
	poc.UpdatedAt = time.Now()

	pm.pocs[poc.ID] = poc
	return nil
}

func (pm *POCManager) RemovePOC(id string) error {
	if _, ok := pm.pocs[id]; !ok {
		return fmt.Errorf("poc not found: %s", id)
	}

	delete(pm.pocs, id)
	return nil
}

func (pm *POCManager) GetPOC(id string) (*POC, error) {
	poc, ok := pm.pocs[id]
	if !ok {
		return nil, fmt.Errorf("poc not found: %s", id)
	}
	return poc, nil
}

func (pm *POCManager) ListPOCs() []*POC {
	pocs := make([]*POC, 0, len(pm.pocs))
	for _, poc := range pm.pocs {
		pocs = append(pocs, poc)
	}
	return pocs
}

func (pm *POCManager) SearchPOCs(keyword string) []*POC {
	var results []*POC

	for _, poc := range pm.pocs {
		if contains(poc.Name, keyword) ||
			contains(poc.Description, keyword) ||
			contains(poc.CVE, keyword) ||
			contains(poc.Author, keyword) {
			results = append(results, poc)
		}
	}

	return results
}

func (pm *POCManager) ExecutePOC(pocID string, target string) (*POCResult, error) {
	poc, err := pm.GetPOC(pocID)
	if err != nil {
		return nil, err
	}

	for _, executor := range pm.executors {
		result, err := executor.Execute(poc, target)
		if err != nil {
			continue
		}
		return result, nil
	}

	return nil, fmt.Errorf("no suitable executor found for POC: %s", pocID)
}

func (pm *POCManager) RegisterExecutor(name string, executor POCExecutor) error {
	if executor == nil {
		return fmt.Errorf("executor cannot be nil")
	}

	pm.executors[name] = executor
	return nil
}

func (pm *POCManager) UnregisterExecutor(name string) error {
	delete(pm.executors, name)
	return nil
}

func (pm *POCManager) LoadPOCFromJSON(data []byte) error {
	var poc POC
	if err := json.Unmarshal(data, &poc); err != nil {
		return fmt.Errorf("failed to unmarshal POC: %w", err)
	}

	return pm.AddPOC(&poc)
}

func (pm *POCManager) LoadPOCsFromJSONFile(filename string) error {
	return fmt.Errorf("not yet implemented")
}

func (pm *POCManager) ExportPOC(id string) ([]byte, error) {
	poc, err := pm.GetPOC(id)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(poc, "", "  ")
}

func (pm *POCManager) ExportAllPOCs() ([]byte, error) {
	pocs := pm.ListPOCs()
	return json.MarshalIndent(pocs, "", "  ")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type POCValidator struct {
	rules []ValidationRule
}

type ValidationRule interface {
	Validate(poc *POC) error
}

func NewPOCValidator() *POCValidator {
	return &POCValidator{
		rules: make([]ValidationRule, 0),
	}
}

func (pv *POCValidator) AddRule(rule ValidationRule) {
	pv.rules = append(pv.rules, rule)
}

func (pv *POCValidator) Validate(poc *POC) error {
	for _, rule := range pv.rules {
		if err := rule.Validate(poc); err != nil {
			return err
		}
	}
	return nil
}

type RequiredFieldRule struct {
	fieldName string
}

func (r *RequiredFieldRule) Validate(poc *POC) error {
	if r.fieldName == "id" && poc.ID == "" {
		return fmt.Errorf("POC ID is required")
	}
	if r.fieldName == "name" && poc.Name == "" {
		return fmt.Errorf("POC name is required")
	}
	if r.fieldName == "author" && poc.Author == "" {
		return fmt.Errorf("POC author is required")
	}
	return nil
}

type CVSSRangeRule struct{}

func (r *CVSSRangeRule) Validate(poc *POC) error {
	if poc.CVSS < 0 || poc.CVSS > 10 {
		return fmt.Errorf("CVSS score must be between 0 and 10")
	}
	return nil
}
