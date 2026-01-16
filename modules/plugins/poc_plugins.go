package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/seaung/pocsuite-go/modules/manager"
)

type POCFromFilePlugin struct {
	*PluginBase
	filename string
	pocs     []string
}

func NewPOCFromFilePlugin(filename string) *POCFromFilePlugin {
	return &POCFromFilePlugin{
		PluginBase: NewPluginBase(CategoryPOCs, "poc_from_file"),
		filename:   filename,
		pocs:       make([]string, 0),
	}
}

func (p *POCFromFilePlugin) Init() error {
	if p.filename == "" {
		return fmt.Errorf("filename not specified")
	}

	data, err := os.ReadFile(p.filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	p.pocs = append(p.pocs, string(data))
	return nil
}

func (p *POCFromFilePlugin) Start() error {
	return nil
}

func (p *POCFromFilePlugin) Stop() error {
	return nil
}

func (p *POCFromFilePlugin) Handle(output interface{}) error {
	return nil
}

func (p *POCFromFilePlugin) AddPOC(poc string) error {
	p.pocs = append(p.pocs, poc)
	return nil
}

func (p *POCFromFilePlugin) AddPOCFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	p.pocs = append(p.pocs, string(data))
	return nil
}

func (p *POCFromFilePlugin) GetPOCs() []string {
	pocs := make([]string, len(p.pocs))
	copy(pocs, p.pocs)
	return pocs
}

type POCFromDirPlugin struct {
	*PluginBase
	directory string
	pocs      []string
}

func NewPOCFromDirPlugin(directory string) *POCFromDirPlugin {
	return &POCFromDirPlugin{
		PluginBase: NewPluginBase(CategoryPOCs, "poc_from_dir"),
		directory:  directory,
		pocs:       make([]string, 0),
	}
}

func (p *POCFromDirPlugin) Init() error {
	if p.directory == "" {
		return fmt.Errorf("directory not specified")
	}

	err := filepath.Walk(p.directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".py" || ext == ".yaml" || ext == ".yml" || ext == ".json" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			p.pocs = append(p.pocs, string(data))
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	return nil
}

func (p *POCFromDirPlugin) Start() error {
	return nil
}

func (p *POCFromDirPlugin) Stop() error {
	return nil
}

func (p *POCFromDirPlugin) Handle(output interface{}) error {
	return nil
}

func (p *POCFromDirPlugin) AddPOC(poc string) error {
	p.pocs = append(p.pocs, poc)
	return nil
}

func (p *POCFromDirPlugin) AddPOCFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	p.pocs = append(p.pocs, string(data))
	return nil
}

func (p *POCFromDirPlugin) GetPOCs() []string {
	pocs := make([]string, len(p.pocs))
	copy(pocs, p.pocs)
	return pocs
}

type POCFromCIDRPlugin struct {
	*PluginBase
	cidr string
	pocs []string
}

func NewPOCFromCIDRPlugin(cidr string) *POCFromCIDRPlugin {
	return &POCFromCIDRPlugin{
		PluginBase: NewPluginBase(CategoryPOCs, "poc_from_cidr"),
		cidr:       cidr,
		pocs:       make([]string, 0),
	}
}

func (p *POCFromCIDRPlugin) Init() error {
	if p.cidr == "" {
		return fmt.Errorf("CIDR not specified")
	}

	return fmt.Errorf("CIDR to PoC mapping not yet implemented")
}

func (p *POCFromCIDRPlugin) Start() error {
	return nil
}

func (p *POCFromCIDRPlugin) Stop() error {
	return nil
}

func (p *POCFromCIDRPlugin) Handle(output interface{}) error {
	return nil
}

func (p *POCFromCIDRPlugin) AddPOC(poc string) error {
	p.pocs = append(p.pocs, poc)
	return nil
}

func (p *POCFromCIDRPlugin) AddPOCFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	p.pocs = append(p.pocs, string(data))
	return nil
}

func (p *POCFromCIDRPlugin) GetPOCs() []string {
	pocs := make([]string, len(p.pocs))
	copy(pocs, p.pocs)
	return pocs
}

type POCFromSeebugPlugin struct {
	*PluginBase
	keyword string
	pocs    []string
}

func NewPOCFromSeebugPlugin(keyword string) *POCFromSeebugPlugin {
	return &POCFromSeebugPlugin{
		PluginBase: NewPluginBase(CategoryPOCs, "poc_from_seebug"),
		keyword:    keyword,
		pocs:       make([]string, 0),
	}
}

func (p *POCFromSeebugPlugin) Init() error {
	if p.keyword == "" {
		return fmt.Errorf("keyword not specified")
	}

	moduleMgr := manager.GetModuleManager()
	seebugModule, ok := moduleMgr.GetVulnerabilityDB("seebug")
	if !ok || seebugModule == nil {
		return fmt.Errorf("seebug module not available")
	}

	if err := seebugModule.Init(); err != nil {
		return fmt.Errorf("failed to initialize seebug module: %w", err)
	}

	if !seebugModule.IsAvailable() {
		return fmt.Errorf("seebug module is not available (check API token)")
	}

	vulnInfo, err := seebugModule.SearchVuln(p.keyword)
	if err != nil {
		return fmt.Errorf("failed to search POCs: %w", err)
	}

	pocs, ok := vulnInfo["pocs"].([]map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid POC data format")
	}

	for _, pocInfo := range pocs {
		ssvid, ok := pocInfo["ssvid"].(string)
		if !ok {
			continue
		}

		p.pocs = append(p.pocs, ssvid)
	}

	return nil
}

func (p *POCFromSeebugPlugin) Start() error {
	return nil
}

func (p *POCFromSeebugPlugin) Stop() error {
	return nil
}

func (p *POCFromSeebugPlugin) Handle(output interface{}) error {
	return nil
}

func (p *POCFromSeebugPlugin) AddPOC(poc string) error {
	p.pocs = append(p.pocs, poc)
	return nil
}

func (p *POCFromSeebugPlugin) AddPOCFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	p.pocs = append(p.pocs, string(data))
	return nil
}

func (p *POCFromSeebugPlugin) GetPOCs() []string {
	pocs := make([]string, len(p.pocs))
	copy(pocs, p.pocs)
	return pocs
}

type POCFromCVEPlugin struct {
	*PluginBase
	cveID string
	pocs  []string
}

func NewPOCFromCVEPlugin(cveID string) *POCFromCVEPlugin {
	return &POCFromCVEPlugin{
		PluginBase: NewPluginBase(CategoryPOCs, "poc_from_cve"),
		cveID:      cveID,
		pocs:       make([]string, 0),
	}
}

func (p *POCFromCVEPlugin) Init() error {
	if p.cveID == "" {
		return fmt.Errorf("CVE ID not specified")
	}

	cveID := strings.ToUpper(strings.TrimSpace(p.cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	pocsDir := "pocs"
	entries, err := os.ReadDir(pocsDir)
	if err != nil {
		return fmt.Errorf("failed to read pocs directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if strings.Contains(strings.ToLower(filename), strings.ToLower(cveID)) {
			filePath := filepath.Join(pocsDir, filename)
			data, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Warning: Failed to read POC file %s: %v\n", filePath, err)
				continue
			}

			p.pocs = append(p.pocs, string(data))
			fmt.Printf("Loaded POC from file: %s\n", filename)
		}
	}

	if len(p.pocs) == 0 {
		return fmt.Errorf("no POCs found for CVE ID: %s", cveID)
	}

	fmt.Printf("Successfully loaded %d POC(s) for CVE ID: %s\n", len(p.pocs), cveID)
	return nil
}

func (p *POCFromCVEPlugin) Start() error {
	return nil
}

func (p *POCFromCVEPlugin) Stop() error {
	return nil
}

func (p *POCFromCVEPlugin) Handle(output interface{}) error {
	return nil
}

func (p *POCFromCVEPlugin) AddPOC(poc string) error {
	p.pocs = append(p.pocs, poc)
	return nil
}

func (p *POCFromCVEPlugin) AddPOCFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	p.pocs = append(p.pocs, string(data))
	return nil
}

func (p *POCFromCVEPlugin) GetPOCs() []string {
	pocs := make([]string, len(p.pocs))
	copy(pocs, p.pocs)
	return pocs
}
