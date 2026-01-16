package core

import (
	"fmt"
	"sync"
)

type Plugin interface {
	GetName() string
	GetVersion() string
	GetDescription() string
	Init() error
	Start() error
	Stop() error
	IsEnabled() bool
	Enable()
	Disable()
}

type PluginBase struct {
	name        string
	version     string
	description string
	enabled     bool
	mu          sync.RWMutex
}

func NewPluginBase(name, version, description string) *PluginBase {
	return &PluginBase{
		name:        name,
		version:     version,
		description: description,
		enabled:     true,
	}
}

func (pb *PluginBase) GetName() string {
	return pb.name
}

func (pb *PluginBase) GetVersion() string {
	return pb.version
}

func (pb *PluginBase) GetDescription() string {
	return pb.description
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

func (pb *PluginBase) IsEnabled() bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	return pb.enabled
}

func (pb *PluginBase) Enable() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.enabled = true
}

func (pb *PluginBase) Disable() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.enabled = false
}

type PluginRegistry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make(map[string]Plugin),
	}
}

func (pr *PluginRegistry) Register(plugin Plugin) error {
	if plugin == nil {
		return fmt.Errorf("plugin cannot be nil")
	}

	name := plugin.GetName()
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if _, exists := pr.plugins[name]; exists {
		return fmt.Errorf("plugin already registered: %s", name)
	}

	pr.plugins[name] = plugin
	return nil
}

func (pr *PluginRegistry) Unregister(name string) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if _, exists := pr.plugins[name]; !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	delete(pr.plugins, name)
	return nil
}

func (pr *PluginRegistry) Get(name string) (Plugin, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	plugin, exists := pr.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}

	return plugin, nil
}

func (pr *PluginRegistry) List() []Plugin {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	plugins := make([]Plugin, 0, len(pr.plugins))
	for _, plugin := range pr.plugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

func (pr *PluginRegistry) ListEnabled() []Plugin {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	plugins := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		if plugin.IsEnabled() {
			plugins = append(plugins, plugin)
		}
	}
	return plugins
}

func (pr *PluginRegistry) ListDisabled() []Plugin {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	plugins := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		if !plugin.IsEnabled() {
			plugins = append(plugins, plugin)
		}
	}
	return plugins
}

func (pr *PluginRegistry) InitAll() error {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	for name, plugin := range pr.plugins {
		if err := plugin.Init(); err != nil {
			return fmt.Errorf("failed to init plugin %s: %w", name, err)
		}
	}
	return nil
}

func (pr *PluginRegistry) StartAll() error {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	for name, plugin := range pr.plugins {
		if plugin.IsEnabled() {
			if err := plugin.Start(); err != nil {
				return fmt.Errorf("failed to start plugin %s: %w", name, err)
			}
		}
	}
	return nil
}

func (pr *PluginRegistry) StopAll() error {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	for name, plugin := range pr.plugins {
		if err := plugin.Stop(); err != nil {
			return fmt.Errorf("failed to stop plugin %s: %w", name, err)
		}
	}
	return nil
}

func (pr *PluginRegistry) Enable(name string) error {
	plugin, err := pr.Get(name)
	if err != nil {
		return err
	}

	plugin.Enable()
	return nil
}

func (pr *PluginRegistry) Disable(name string) error {
	plugin, err := pr.Get(name)
	if err != nil {
		return err
	}

	plugin.Disable()
	return nil
}

func (pr *PluginRegistry) Count() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.plugins)
}

func (pr *PluginRegistry) CountEnabled() int {
	return len(pr.ListEnabled())
}

func (pr *PluginRegistry) CountDisabled() int {
	return len(pr.ListDisabled())
}

func (pr *PluginRegistry) Clear() {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.plugins = make(map[string]Plugin)
}

type PluginLoader struct {
	registry *PluginRegistry
}

func NewPluginLoader(registry *PluginRegistry) *PluginLoader {
	return &PluginLoader{
		registry: registry,
	}
}

func (pl *PluginLoader) Load(plugin Plugin) error {
	if err := pl.registry.Register(plugin); err != nil {
		return fmt.Errorf("failed to register plugin: %w", err)
	}

	if err := plugin.Init(); err != nil {
		return fmt.Errorf("failed to init plugin: %w", err)
	}

	return nil
}

func (pl *PluginLoader) LoadAndStart(plugin Plugin) error {
	if err := pl.Load(plugin); err != nil {
		return err
	}

	if err := plugin.Start(); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	return nil
}

func (pl *PluginLoader) Unload(name string) error {
	plugin, err := pl.registry.Get(name)
	if err != nil {
		return err
	}

	if err := plugin.Stop(); err != nil {
		return fmt.Errorf("failed to stop plugin: %w", err)
	}

	if err := pl.registry.Unregister(name); err != nil {
		return err
	}

	return nil
}

type PluginHook struct {
	name     string
	handlers []func(interface{}) error
	mu       sync.RWMutex
}

func NewPluginHook(name string) *PluginHook {
	return &PluginHook{
		name:     name,
		handlers: make([]func(interface{}) error, 0),
	}
}

func (ph *PluginHook) GetName() string {
	return ph.name
}

func (ph *PluginHook) Register(handler func(interface{}) error) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.handlers = append(ph.handlers, handler)
}

func (ph *PluginHook) Unregister(index int) {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	if index >= 0 && index < len(ph.handlers) {
		ph.handlers = append(ph.handlers[:index], ph.handlers[index+1:]...)
	}
}

func (ph *PluginHook) Trigger(data interface{}) error {
	ph.mu.RLock()
	handlers := make([]func(interface{}) error, len(ph.handlers))
	copy(handlers, ph.handlers)
	ph.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler(data); err != nil {
			return err
		}
	}
	return nil
}

func (ph *PluginHook) Clear() {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.handlers = make([]func(interface{}) error, 0)
}

func (ph *PluginHook) Count() int {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return len(ph.handlers)
}
