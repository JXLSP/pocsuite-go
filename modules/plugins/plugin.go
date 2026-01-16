package plugins

import (
	"fmt"
)

type PluginCategory string

const (
	CategoryTargets PluginCategory = "targets"
	CategoryPOCs    PluginCategory = "pocs"
	CategoryResults PluginCategory = "results"
)

type Plugin interface {
	GetCategory() PluginCategory
	GetName() string
	Init() error
	Start() error
	Stop() error
	Handle(output interface{}) error
}

type PluginBase struct {
	category PluginCategory
	name     string
	enabled  bool
}

func NewPluginBase(category PluginCategory, name string) *PluginBase {
	return &PluginBase{
		category: category,
		name:     name,
		enabled:  true,
	}
}

func (pb *PluginBase) GetCategory() PluginCategory {
	return pb.category
}

func (pb *PluginBase) GetName() string {
	return pb.name
}

func (pb *PluginBase) Init() error {
	return nil
}

func (pb *PluginBase) Start() error {
	return nil
}

func (pb *PluginBase) Stop() error {
	return nil
}

func (pb *PluginBase) Handle(output interface{}) error {
	return nil
}

func (pb *PluginBase) IsEnabled() bool {
	return pb.enabled
}

func (pb *PluginBase) Enable() {
	pb.enabled = true
}

func (pb *PluginBase) Disable() {
	pb.enabled = false
}

type TargetPlugin interface {
	Plugin
	AddTarget(target string) error
	GetTargets() []string
}

type POCPlugin interface {
	Plugin
	AddPOC(poc string) error
	AddPOCFromFile(filename string) error
	GetPOCs() []string
}

type ResultPlugin interface {
	Plugin
	AddResult(result interface{}) error
	GetResults() []interface{}
	Export(filename string) error
}

type PluginManager struct {
	targetPlugins map[string]TargetPlugin
	pocPlugins    map[string]POCPlugin
	resultPlugins map[string]ResultPlugin
}

func NewPluginManager() *PluginManager {
	return &PluginManager{
		targetPlugins: make(map[string]TargetPlugin),
		pocPlugins:    make(map[string]POCPlugin),
		resultPlugins: make(map[string]ResultPlugin),
	}
}

func (pm *PluginManager) RegisterPlugin(plugin Plugin) error {
	switch p := plugin.(type) {
	case TargetPlugin:
		pm.targetPlugins[p.GetName()] = p
	case POCPlugin:
		pm.pocPlugins[p.GetName()] = p
	case ResultPlugin:
		pm.resultPlugins[p.GetName()] = p
	default:
		return fmt.Errorf("unsupported plugin type: %T", plugin)
	}
	return nil
}

func (pm *PluginManager) UnregisterPlugin(name string) error {
	delete(pm.targetPlugins, name)
	delete(pm.pocPlugins, name)
	delete(pm.resultPlugins, name)
	return nil
}

func (pm *PluginManager) GetPlugin(name string) (Plugin, error) {
	if p, ok := pm.targetPlugins[name]; ok {
		return p, nil
	}
	if p, ok := pm.pocPlugins[name]; ok {
		return p, nil
	}
	if p, ok := pm.resultPlugins[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("plugin not found: %s", name)
}

func (pm *PluginManager) GetTargetPlugins() []TargetPlugin {
	plugins := make([]TargetPlugin, 0, len(pm.targetPlugins))
	for _, p := range pm.targetPlugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (pm *PluginManager) GetPOCPlugins() []POCPlugin {
	plugins := make([]POCPlugin, 0, len(pm.pocPlugins))
	for _, p := range pm.pocPlugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (pm *PluginManager) GetResultPlugins() []ResultPlugin {
	plugins := make([]ResultPlugin, 0, len(pm.resultPlugins))
	for _, p := range pm.resultPlugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (pm *PluginManager) GetResultPlugin(name string) (ResultPlugin, error) {
	if p, ok := pm.resultPlugins[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("result plugin not found: %s", name)
}

func (pm *PluginManager) InitAll() error {
	for _, p := range pm.targetPlugins {
		if err := p.Init(); err != nil {
			return fmt.Errorf("failed to init target plugin %s: %w", p.GetName(), err)
		}
	}
	for _, p := range pm.pocPlugins {
		if err := p.Init(); err != nil {
			return fmt.Errorf("failed to init poc plugin %s: %w", p.GetName(), err)
		}
	}
	for _, p := range pm.resultPlugins {
		if err := p.Init(); err != nil {
			return fmt.Errorf("failed to init result plugin %s: %w", p.GetName(), err)
		}
	}
	return nil
}

func (pm *PluginManager) StartAll() error {
	for _, p := range pm.targetPlugins {
		if err := p.Start(); err != nil {
			return fmt.Errorf("failed to start target plugin %s: %w", p.GetName(), err)
		}
	}
	for _, p := range pm.pocPlugins {
		if err := p.Start(); err != nil {
			return fmt.Errorf("failed to start poc plugin %s: %w", p.GetName(), err)
		}
	}
	for _, p := range pm.resultPlugins {
		if err := p.Start(); err != nil {
			return fmt.Errorf("failed to start result plugin %s: %w", p.GetName(), err)
		}
	}
	return nil
}

func (pm *PluginManager) StopAll() error {
	for _, p := range pm.targetPlugins {
		if err := p.Stop(); err != nil {
			return fmt.Errorf("failed to stop target plugin %s: %w", p.GetName(), err)
		}
	}
	for _, p := range pm.pocPlugins {
		if err := p.Stop(); err != nil {
			return fmt.Errorf("failed to stop poc plugin %s: %w", p.GetName(), err)
		}
	}
	for _, p := range pm.resultPlugins {
		if err := p.Stop(); err != nil {
			return fmt.Errorf("failed to stop result plugin %s: %w", p.GetName(), err)
		}
	}
	return nil
}

func (pm *PluginManager) HandleAll(output interface{}) error {
	for _, p := range pm.resultPlugins {
		if err := p.Handle(output); err != nil {
			return fmt.Errorf("failed to handle output with plugin %s: %w", p.GetName(), err)
		}
	}
	return nil
}

var GlobalPluginManager = NewPluginManager()

func GetPluginManager() *PluginManager {
	return GlobalPluginManager
}
