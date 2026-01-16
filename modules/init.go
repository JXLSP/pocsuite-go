package modules

import (
	"fmt"

	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/modules/censys"
	"github.com/seaung/pocsuite-go/modules/ceye"
	"github.com/seaung/pocsuite-go/modules/fofa"
	"github.com/seaung/pocsuite-go/modules/httpserver"
	"github.com/seaung/pocsuite-go/modules/hunter"
	"github.com/seaung/pocsuite-go/modules/interactsh"
	"github.com/seaung/pocsuite-go/modules/listener"
	"github.com/seaung/pocsuite-go/modules/manager"
	"github.com/seaung/pocsuite-go/modules/plugins"
	"github.com/seaung/pocsuite-go/modules/quake"
	"github.com/seaung/pocsuite-go/modules/seebug"
	"github.com/seaung/pocsuite-go/modules/shellcodes"
	"github.com/seaung/pocsuite-go/modules/shodan"
	"github.com/seaung/pocsuite-go/modules/spider"
	"github.com/seaung/pocsuite-go/modules/zoomeye"
)

var GlobalConfig *config.Config

func InitConfig() error {
	configPath := config.GetDefaultConfigPath()
	cfg, err := config.NewConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}
	GlobalConfig = cfg

	manager.GlobalManager = manager.NewModuleManager()

	return nil
}

func InitModules() error {
	if err := InitConfig(); err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	if err := registerSearchModules(); err != nil {
		return fmt.Errorf("failed to register search modules: %w", err)
	}

	if err := registerOASTModules(); err != nil {
		return fmt.Errorf("failed to register OAST modules: %w", err)
	}

	if err := registerVulnDBModules(); err != nil {
		return fmt.Errorf("failed to register vulnerability database modules: %w", err)
	}

	if err := registerHTTPServerModules(); err != nil {
		return fmt.Errorf("failed to register HTTP server modules: %w", err)
	}

	if err := registerListenerModules(); err != nil {
		return fmt.Errorf("failed to register listener modules: %w", err)
	}

	if err := registerSpiderModules(); err != nil {
		return fmt.Errorf("failed to register spider modules: %w", err)
	}

	if err := registerShellcodesModules(); err != nil {
		return fmt.Errorf("failed to register shellcodes modules: %w", err)
	}

	if err := registerPlugins(); err != nil {
		return fmt.Errorf("failed to register plugins: %w", err)
	}

	return nil
}

func registerSearchModules() error {
	searchModules := []Searcher{
		shodan.New(GlobalConfig),
		zoomeye.New(GlobalConfig),
		censys.New(GlobalConfig),
		fofa.New(GlobalConfig),
		hunter.New(GlobalConfig),
		quake.New(GlobalConfig),
	}

	for _, module := range searchModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func registerOASTModules() error {
	oastModules := []OASTService{
		interactsh.New(GlobalConfig),
		ceye.New(GlobalConfig),
	}

	for _, module := range oastModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func registerVulnDBModules() error {
	vulnDBModules := []VulnerabilityDB{
		seebug.New(GlobalConfig),
	}

	for _, module := range vulnDBModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func registerHTTPServerModules() error {
	httpServerModules := []HTTPServer{
		httpserver.New(GlobalConfig),
	}

	for _, module := range httpServerModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func registerListenerModules() error {
	listenerModules := []Listener{
		listener.NewBindTCP(GlobalConfig),
		listener.NewReverseTCP(GlobalConfig),
	}

	for _, module := range listenerModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func registerSpiderModules() error {
	spiderModules := []Spider{
		spider.New(GlobalConfig),
	}

	for _, module := range spiderModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func registerShellcodesModules() error {
	shellcodesModules := []Shellcodes{
		shellcodes.New(GlobalConfig),
	}

	for _, module := range shellcodesModules {
		if err := manager.GlobalManager.Register(module); err != nil {
			return err
		}
	}

	return nil
}

func GetAvailableModules() []string {
	return manager.GlobalManager.List()
}

func GetModuleInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["searchers"] = []string{"shodan", "zoomeye", "censys", "fofa", "hunter", "quake"}

	info["oast_services"] = []string{"interactsh", "ceye"}

	info["vuln_dbs"] = []string{"seebug"}

	info["http_servers"] = []string{"httpserver"}

	info["listeners"] = []string{"bind_tcp", "reverse_tcp"}

	info["spiders"] = []string{"spider"}

	info["shellcodes"] = []string{"shellcodes"}

	info["plugins"] = []string{
		"file_record", "html_report", "console_output",
		"poc_from_file", "poc_from_dir", "poc_from_seebug", "poc_from_cve",
		"target_from_file", "target_from_cidr", "target_from_censys", "target_from_shodan", "target_from_fofa", "target_from_ceye", "target_from_zoomeye",
	}

	return info
}

func registerPlugins() error {
	pluginMgr := plugins.GetPluginManager()

	resultPlugins := []plugins.Plugin{
		plugins.NewFileRecordPlugin(""),
		plugins.NewHTMLReportPlugin(),
		plugins.NewConsoleOutputPlugin(),
	}

	for _, plugin := range resultPlugins {
		if err := pluginMgr.RegisterPlugin(plugin); err != nil {
			return fmt.Errorf("failed to register result plugin %s: %w", plugin.GetName(), err)
		}
	}

	pocPlugins := []plugins.Plugin{
		plugins.NewPOCFromFilePlugin(""),
		plugins.NewPOCFromDirPlugin(""),
	}

	for _, plugin := range pocPlugins {
		if err := pluginMgr.RegisterPlugin(plugin); err != nil {
			return fmt.Errorf("failed to register POC plugin %s: %w", plugin.GetName(), err)
		}
	}

	targetPlugins := []plugins.Plugin{
		plugins.NewTargetFromFilePlugin(""),
		plugins.NewTargetFromCIDRPlugin(""),
	}

	for _, plugin := range targetPlugins {
		if err := pluginMgr.RegisterPlugin(plugin); err != nil {
			return fmt.Errorf("failed to register target plugin %s: %w", plugin.GetName(), err)
		}
	}

	return nil
}
