package core

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seaung/pocsuite-go/api"
	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/modules"
	"github.com/seaung/pocsuite-go/modules/httpserver"
	"github.com/seaung/pocsuite-go/modules/interfaces"
	"github.com/seaung/pocsuite-go/modules/listener"
	"github.com/seaung/pocsuite-go/modules/manager"
	"github.com/seaung/pocsuite-go/modules/plugins"
	"github.com/seaung/pocsuite-go/modules/spider"
	"github.com/seaung/pocsuite-go/registry"
)

type Controller struct {
	config        *config.Config
	moduleMgr     *modules.ModuleManager
	pluginMgr     *plugins.PluginManager
	pocLoader     *POCLoader
	listenerMgr   *listener.ListenerManager
	spiderMgr     *spider.Spider
	httpServerMgr *httpserver.HTTPServer
	results       []*api.Output
	mu            sync.RWMutex
	options       map[string]interface{}
}

func NewController(cfg *config.Config) (*Controller, error) {
	moduleMgr := manager.GetModuleManager()
	pluginMgr := plugins.GetPluginManager()
	pocLoader := NewPOCLoader()
	listenerMgr := listener.New(cfg)
	spiderMgr := spider.New(cfg)
	httpServerMgr := httpserver.New(cfg)

	return &Controller{
		config:        cfg,
		moduleMgr:     moduleMgr,
		pluginMgr:     pluginMgr,
		pocLoader:     pocLoader,
		listenerMgr:   listenerMgr,
		spiderMgr:     spiderMgr,
		httpServerMgr: httpServerMgr,
		results:       make([]*api.Output, 0),
		options:       make(map[string]interface{}),
	}, nil
}

func (c *Controller) Initialize() error {
	if err := c.moduleMgr.InitAll(); err != nil {
		fmt.Printf("Warning: Some modules failed to initialize: %v\n", err)
	}

	if err := c.pluginMgr.InitAll(); err != nil {
		fmt.Printf("Warning: Some plugins failed to initialize: %v\n", err)
	}

	if bindTCP, ok := c.moduleMgr.GetListener("bind_tcp"); ok {
		c.listenerMgr.RegisterListener("bind_tcp", bindTCP)
	}
	if reverseTCP, ok := c.moduleMgr.GetListener("reverse_tcp"); ok {
		c.listenerMgr.RegisterListener("reverse_tcp", reverseTCP)
	}

	return nil
}

func (c *Controller) SetOption(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.options[key] = value
}

func (c *Controller) GetOption(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.options[key]
	return val, ok
}

func (c *Controller) LoadPOC(pocPath string) (string, error) {
	return c.pocLoader.LoadFromFile(pocPath)
}

func (c *Controller) LoadPOCsFromDir(dir string) ([]string, error) {
	return c.pocLoader.LoadFromDir(dir)
}

func (c *Controller) LoadPOCsFromFiles(pocPaths []string) ([]string, error) {
	return c.pocLoader.LoadFromFiles(pocPaths)
}

func (c *Controller) GetLoadedPOCs() []string {
	return c.pocLoader.GetLoadedPOCs()
}

func (c *Controller) UnloadPOC(pocName string) error {
	return c.pocLoader.Unload(pocName)
}

func (c *Controller) ClearPOCs() {
	c.pocLoader.Clear()
}

func (c *Controller) GetPOCCount() int {
	return c.pocLoader.Count()
}

func (c *Controller) ExecutePOC(pocName, target string, mode string) (*api.Output, error) {
	poc, exists := registry.Get(pocName)
	if !exists {
		return nil, fmt.Errorf("POC '%s' not found", pocName)
	}

	options := make(map[string]interface{})
	c.mu.RLock()
	for k, v := range c.options {
		options[k] = v
	}
	c.mu.RUnlock()

	if oastDomain, err := c.GetOASTDomain(); err == nil && oastDomain != "" {
		options["oast_domain"] = oastDomain
	}
	if oastURL, err := c.GetOASTURL(); err == nil && oastURL != "" {
		options["oast_url"] = oastURL
	}

	var output *api.Output
	var err error

	switch mode {
	case "verify":
		output, err = poc.Verify(target, options)
	case "attack":
		output, err = poc.Attack(target, options)
	case "shell":
		output, err = poc.Shell(target, options)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}

	if err != nil {
		return nil, fmt.Errorf("POC execution failed: %w", err)
	}

	c.mu.Lock()
	c.results = append(c.results, output)
	c.mu.Unlock()

	c.notifyPlugins(output)

	return output, nil
}

func (c *Controller) SearchTargets(searcherName, query string) ([]string, error) {
	searcher, ok := c.moduleMgr.GetSearcher(searcherName)
	if !ok {
		return nil, fmt.Errorf("searcher '%s' not found", searcherName)
	}

	if !searcher.IsAvailable() {
		return nil, fmt.Errorf("searcher '%s' is not available", searcherName)
	}

	targets, err := searcher.Search(query, 1, "host")
	if err != nil {
		return nil, err
	}

	return targets, nil
}

func (c *Controller) GetResults() []*api.Output {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.results
}

func (c *Controller) ClearResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = make([]*api.Output, 0)
}

func (c *Controller) notifyPlugins(output *api.Output) {
	resultPlugins := c.pluginMgr.GetResultPlugins()
	for _, plugin := range resultPlugins {
		plugin.Handle(output)
	}
}

func (c *Controller) GetOASTDomain() (string, error) {
	if interactsh, ok := c.moduleMgr.GetOASTService("interactsh"); ok && interactsh.IsAvailable() {
		return interactsh.GetDomain(), nil
	}

	if ceye, ok := c.moduleMgr.GetOASTService("ceye"); ok && ceye.IsAvailable() {
		return ceye.GetDomain(), nil
	}

	return "", fmt.Errorf("no available OAST service")
}

func (c *Controller) GetOASTURL() (string, error) {
	if interactsh, ok := c.moduleMgr.GetOASTService("interactsh"); ok && interactsh.IsAvailable() {
		return interactsh.GetURL(), nil
	}

	if ceye, ok := c.moduleMgr.GetOASTService("ceye"); ok && ceye.IsAvailable() {
		return ceye.GetURL(), nil
	}

	return "", fmt.Errorf("no available OAST service")
}

func (c *Controller) CheckOASTInteraction() (bool, error) {
	if interactsh, ok := c.moduleMgr.GetOASTService("interactsh"); ok && interactsh.IsAvailable() {
		return interactsh.CheckInteraction(), nil
	}

	if ceye, ok := c.moduleMgr.GetOASTService("ceye"); ok && ceye.IsAvailable() {
		return ceye.CheckInteraction(), nil
	}

	return false, fmt.Errorf("no available OAST service")
}

func (c *Controller) Shutdown() error {
	c.listenerMgr.StopAll()
	c.listenerMgr.CloseAllClients()

	if htmlPlugin, err := c.pluginMgr.GetResultPlugin("html_report"); err == nil {
		if htmlExporter, ok := htmlPlugin.(interface{ Export(string) error }); ok {
			if err := htmlExporter.Export(""); err != nil {
				fmt.Printf("Warning: failed to export HTML report: %v\n", err)
			}
		}
	}

	if err := c.pluginMgr.StopAll(); err != nil {
		return fmt.Errorf("failed to stop plugins: %w", err)
	}

	c.ClearResults()

	return nil
}

func (c *Controller) StartListener(name string) error {
	listener, err := c.listenerMgr.GetListener(name)
	if err != nil {
		return err
	}

	if name == "reverse_tcp" {
		if portStr, ok := c.GetOption("reverse_tcp_port"); ok {
			if port, err := strconv.Atoi(portStr.(string)); err == nil {
				if rtcp, ok := listener.(interface{ SetListenPort(int) }); ok {
					rtcp.SetListenPort(port)
				}
			}
		}
	}

	if name == "bind_tcp" {
		if address, ok := c.GetOption("bind_tcp_address"); ok {
			parts := strings.Split(address.(string), ":")
			if len(parts) == 2 {
				host := parts[0]
				if port, err := strconv.Atoi(parts[1]); err == nil {
					if btcp, ok := listener.(interface{ SetBindHost(string) }); ok {
						btcp.SetBindHost(host)
					}
					if btcp, ok := listener.(interface{ SetBindPort(int) }); ok {
						btcp.SetBindPort(port)
					}
				}
			}
		}
	}

	return c.listenerMgr.StartListener(name)
}

func (c *Controller) StopListener(name string) error {
	return c.listenerMgr.StopListener(name)
}

func (c *Controller) StopAllListeners() {
	c.listenerMgr.StopAll()
}

func (c *Controller) ListClients() []interfaces.Client {
	return c.listenerMgr.ListClients()
}

func (c *Controller) SendCommand(clientIndex int, command string) error {
	client, err := c.listenerMgr.GetClient(clientIndex)
	if err != nil {
		return err
	}
	return c.listenerMgr.SendCommand(client, command)
}

func (c *Controller) ReadResponse(clientIndex int, timeout time.Duration) (string, error) {
	client, err := c.listenerMgr.GetClient(clientIndex)
	if err != nil {
		return "", err
	}
	return c.listenerMgr.ReadResponse(client, timeout)
}

func (c *Controller) CrawlURL(targetURL string, depth int) ([]string, error) {
	if err := c.spiderMgr.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize spider: %w", err)
	}

	if !c.spiderMgr.IsAvailable() {
		return nil, fmt.Errorf("spider module is not available")
	}

	urls, err := c.spiderMgr.Crawl(targetURL, depth)
	if err != nil {
		return nil, fmt.Errorf("crawling failed: %w", err)
	}

	return urls, nil
}

func (c *Controller) GetRedirectURL(targetURL string) (string, error) {
	if err := c.spiderMgr.Init(); err != nil {
		return "", fmt.Errorf("failed to initialize spider: %w", err)
	}

	if !c.spiderMgr.IsAvailable() {
		return "", fmt.Errorf("spider module is not available")
	}

	redirectURL, err := c.spiderMgr.GetRedirectURL(targetURL)
	if err != nil {
		return "", fmt.Errorf("failed to get redirect URL: %w", err)
	}

	return redirectURL, nil
}

func (c *Controller) StartHTTPServer(port int) error {
	if err := c.httpServerMgr.Init(); err != nil {
		return fmt.Errorf("failed to initialize HTTP server: %w", err)
	}

	if err := c.httpServerMgr.Start(port); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	return nil
}

func (c *Controller) StopHTTPServer() error {
	if err := c.httpServerMgr.Stop(); err != nil {
		return fmt.Errorf("failed to stop HTTP server: %w", err)
	}
	return nil
}

func (c *Controller) GetHTTPServerURL() string {
	return c.httpServerMgr.GetURL()
}

func (c *Controller) GetHTTPServerHostIP() string {
	return c.httpServerMgr.GetHostIP()
}
