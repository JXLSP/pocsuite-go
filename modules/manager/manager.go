package manager

import (
	"fmt"

	"github.com/seaung/pocsuite-go/modules/interfaces"
)

var GlobalManager *ModuleManager

type ModuleManager struct {
	modules map[string]interfaces.Module
}

func NewModuleManager() *ModuleManager {
	return &ModuleManager{
		modules: make(map[string]interfaces.Module),
	}
}

func (m *ModuleManager) Register(module interfaces.Module) error {
	name := module.Name()
	if _, exists := m.modules[name]; exists {
		return fmt.Errorf("module %s already registered", name)
	}
	m.modules[name] = module
	return nil
}

func (m *ModuleManager) Get(name string) (interfaces.Module, bool) {
	module, exists := m.modules[name]
	return module, exists
}

func (m *ModuleManager) GetSearcher(name string) (interfaces.Searcher, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	searcher, ok := module.(interfaces.Searcher)
	return searcher, ok
}

func (m *ModuleManager) GetOASTService(name string) (interfaces.OASTService, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	service, ok := module.(interfaces.OASTService)
	return service, ok
}

func (m *ModuleManager) GetVulnerabilityDB(name string) (interfaces.VulnerabilityDB, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	db, ok := module.(interfaces.VulnerabilityDB)
	return db, ok
}

func (m *ModuleManager) GetHTTPServer(name string) (interfaces.HTTPServer, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	server, ok := module.(interfaces.HTTPServer)
	return server, ok
}

func (m *ModuleManager) GetListener(name string) (interfaces.ListenerModule, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	listener, ok := module.(interfaces.ListenerModule)
	return listener, ok
}

func (m *ModuleManager) GetSpider(name string) (interfaces.Spider, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	spider, ok := module.(interfaces.Spider)
	return spider, ok
}

func (m *ModuleManager) GetShellcodes(name string) (interfaces.Shellcodes, bool) {
	module, exists := m.modules[name]
	if !exists {
		return nil, false
	}
	shellcodes, ok := module.(interfaces.Shellcodes)
	return shellcodes, ok
}

func (m *ModuleManager) List() []string {
	names := make([]string, 0, len(m.modules))
	for name := range m.modules {
		names = append(names, name)
	}
	return names
}

func (m *ModuleManager) InitAll() error {
	for name, module := range m.modules {
		if err := module.Init(); err != nil {
			return fmt.Errorf("failed to initialize module %s: %w", name, err)
		}
	}
	return nil
}

func GetModuleManager() *ModuleManager {
	return GlobalManager
}
