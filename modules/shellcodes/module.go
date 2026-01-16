package shellcodes

import (
	"fmt"

	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/modules/interfaces"
)

type Module struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Module {
	return &Module{
		cfg: cfg,
	}
}

func (m *Module) Name() string {
	return "shellcodes"
}

func (m *Module) Init() error {
	return nil
}

func (m *Module) IsAvailable() bool {
	return true
}

func (m *Module) CreateOSShellcode(osTarget string, arch string, shellcodeType string, connectbackIP string, connectbackPort int, encoding string) ([]byte, error) {
	os := OS(osTarget)
	archType := Arch(arch)
	scType := ShellcodeType(shellcodeType)

	osShellcodes, err := NewOSShellcodes(os, archType)
	if err != nil {
		return nil, fmt.Errorf("failed to create OS shellcodes: %w", err)
	}

	shellcode, err := osShellcodes.CreateShellcode(scType, connectbackIP, connectbackPort, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to create shellcode: %w", err)
	}

	return shellcode, nil
}

func (m *Module) CreateExe(osTarget string, arch string, shellcodeType string, connectbackIP string, connectbackPort int, filename string) ([]byte, error) {
	os := OS(osTarget)
	archType := Arch(arch)
	scType := ShellcodeType(shellcodeType)

	osShellcodes, err := NewOSShellcodes(os, archType)
	if err != nil {
		return nil, fmt.Errorf("failed to create OS shellcodes: %w", err)
	}

	exeData, err := osShellcodes.CreateExe(scType, connectbackIP, connectbackPort, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create exe: %w", err)
	}

	return exeData, nil
}

func (m *Module) CreateWebShell(webShellType string, password string) (string, error) {
	wsType := WebShellType(webShellType)

	webShell, err := NewWebShell(wsType)
	if err != nil {
		return "", fmt.Errorf("failed to create webshell: %w", err)
	}

	webshellCode, err := webShell.CreateWebShell(password)
	if err != nil {
		return "", fmt.Errorf("failed to create webshell: %w", err)
	}

	return webshellCode, nil
}

var _ interfaces.Shellcodes = (*Module)(nil)
