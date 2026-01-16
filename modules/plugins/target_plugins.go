package plugins

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/seaung/pocsuite-go/modules/manager"
)

type TargetFromFilePlugin struct {
	*PluginBase
	filename string
	targets  []string
}

func NewTargetFromFilePlugin(filename string) *TargetFromFilePlugin {
	return &TargetFromFilePlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_file"),
		filename:   filename,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromFilePlugin) Init() error {
	if p.filename == "" {
		return fmt.Errorf("filename not specified")
	}

	file, err := os.Open(p.filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			p.targets = append(p.targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	return nil
}

func (p *TargetFromFilePlugin) Start() error {
	return nil
}

func (p *TargetFromFilePlugin) Stop() error {
	return nil
}

func (p *TargetFromFilePlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromFilePlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromFilePlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

type TargetFromCensysPlugin struct {
	*PluginBase
	query   string
	targets []string
}

func NewTargetFromCensysPlugin(query string) *TargetFromCensysPlugin {
	return &TargetFromCensysPlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_censys"),
		query:      query,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromCensysPlugin) Init() error {
	if p.query == "" {
		return fmt.Errorf("query not specified")
	}

	moduleMgr := manager.GetModuleManager()
	censysModule, ok := moduleMgr.GetSearcher("censys")
	if !ok || censysModule == nil {
		return fmt.Errorf("censys module not available")
	}

	if err := censysModule.Init(); err != nil {
		return fmt.Errorf("failed to initialize censys module: %w", err)
	}

	if !censysModule.IsAvailable() {
		return fmt.Errorf("censys module is not available (check API token)")
	}

	results, err := censysModule.Search(p.query, 100, "host")
	if err != nil {
		return fmt.Errorf("failed to search targets: %w", err)
	}

	p.targets = results
	return nil
}

func (p *TargetFromCensysPlugin) Start() error {
	return nil
}

func (p *TargetFromCensysPlugin) Stop() error {
	return nil
}

func (p *TargetFromCensysPlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromCensysPlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromCensysPlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

type TargetFromShodanPlugin struct {
	*PluginBase
	query   string
	targets []string
}

func NewTargetFromShodanPlugin(query string) *TargetFromShodanPlugin {
	return &TargetFromShodanPlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_shodan"),
		query:      query,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromShodanPlugin) Init() error {
	if p.query == "" {
		return fmt.Errorf("query not specified")
	}

	moduleMgr := manager.GetModuleManager()
	shodanModule, ok := moduleMgr.GetSearcher("shodan")
	if !ok || shodanModule == nil {
		return fmt.Errorf("shodan module not available")
	}

	if err := shodanModule.Init(); err != nil {
		return fmt.Errorf("failed to initialize shodan module: %w", err)
	}

	if !shodanModule.IsAvailable() {
		return fmt.Errorf("shodan module is not available (check API token)")
	}

	results, err := shodanModule.Search(p.query, 100, "host")
	if err != nil {
		return fmt.Errorf("failed to search targets: %w", err)
	}

	p.targets = results
	return nil
}

func (p *TargetFromShodanPlugin) Start() error {
	return nil
}

func (p *TargetFromShodanPlugin) Stop() error {
	return nil
}

func (p *TargetFromShodanPlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromShodanPlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromShodanPlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

type TargetFromFofaPlugin struct {
	*PluginBase
	query   string
	targets []string
}

func NewTargetFromFofaPlugin(query string) *TargetFromFofaPlugin {
	return &TargetFromFofaPlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_fofa"),
		query:      query,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromFofaPlugin) Init() error {
	if p.query == "" {
		return fmt.Errorf("query not specified")
	}

	moduleMgr := manager.GetModuleManager()
	fofaModule, ok := moduleMgr.GetSearcher("fofa")
	if !ok || fofaModule == nil {
		return fmt.Errorf("fofa module not available")
	}

	if err := fofaModule.Init(); err != nil {
		return fmt.Errorf("failed to initialize fofa module: %w", err)
	}

	if !fofaModule.IsAvailable() {
		return fmt.Errorf("fofa module is not available (check API token)")
	}

	results, err := fofaModule.Search(p.query, 100, "host")
	if err != nil {
		return fmt.Errorf("failed to search targets: %w", err)
	}

	p.targets = results
	return nil
}

func (p *TargetFromFofaPlugin) Start() error {
	return nil
}

func (p *TargetFromFofaPlugin) Stop() error {
	return nil
}

func (p *TargetFromFofaPlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromFofaPlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromFofaPlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

type TargetFromCEyePlugin struct {
	*PluginBase
	query   string
	targets []string
}

func NewTargetFromCEyePlugin(query string) *TargetFromCEyePlugin {
	return &TargetFromCEyePlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_ceye"),
		query:      query,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromCEyePlugin) Init() error {
	return fmt.Errorf("CEye API integration not yet implemented")
}

func (p *TargetFromCEyePlugin) Start() error {
	return nil
}

func (p *TargetFromCEyePlugin) Stop() error {
	return nil
}

func (p *TargetFromCEyePlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromCEyePlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromCEyePlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

type TargetFromZoomEyePlugin struct {
	*PluginBase
	query   string
	targets []string
}

func NewTargetFromZoomEyePlugin(query string) *TargetFromZoomEyePlugin {
	return &TargetFromZoomEyePlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_zoomeye"),
		query:      query,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromZoomEyePlugin) Init() error {
	return fmt.Errorf("ZoomEye API integration not yet implemented")
}

func (p *TargetFromZoomEyePlugin) Start() error {
	return nil
}

func (p *TargetFromZoomEyePlugin) Stop() error {
	return nil
}

func (p *TargetFromZoomEyePlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromZoomEyePlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromZoomEyePlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

type TargetFromCIDRPlugin struct {
	*PluginBase
	cidr    string
	targets []string
}

func NewTargetFromCIDRPlugin(cidr string) *TargetFromCIDRPlugin {
	return &TargetFromCIDRPlugin{
		PluginBase: NewPluginBase(CategoryTargets, "target_from_cidr"),
		cidr:       cidr,
		targets:    make([]string, 0),
	}
}

func (p *TargetFromCIDRPlugin) Init() error {
	if p.cidr == "" {
		return fmt.Errorf("CIDR not specified")
	}

	ips, err := expandCIDR(p.cidr)
	if err != nil {
		return fmt.Errorf("failed to expand CIDR: %w", err)
	}

	p.targets = ips
	return nil
}

func (p *TargetFromCIDRPlugin) Start() error {
	return nil
}

func (p *TargetFromCIDRPlugin) Stop() error {
	return nil
}

func (p *TargetFromCIDRPlugin) Handle(output interface{}) error {
	return nil
}

func (p *TargetFromCIDRPlugin) AddTarget(target string) error {
	p.targets = append(p.targets, target)
	return nil
}

func (p *TargetFromCIDRPlugin) GetTargets() []string {
	targets := make([]string, len(p.targets))
	copy(targets, p.targets)
	return targets
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format: %w", err)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	if ipnet.IP.To4() != nil && len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
