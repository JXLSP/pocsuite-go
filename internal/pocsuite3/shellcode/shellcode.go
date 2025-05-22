package shellcode

import (
	"fmt"
	"strings"
)

type ShellCoder interface {
	GenShellCode(code string) (string, error)
	MakeInline(payloads string) string
	GetShellCode(inline bool) (string, error)
	Validate() error
}

type ShellCodeBase struct {
	Target       string
	Arch         string
	IP           string
	Port         int
	Name         string
	Prefix       string
	Suffix       string
	BadChars     string
	TemplateVars map[string]string
}

// NewShellCodeBase 创建一个新的ShellCodeBase实例
func NewShellCodeBase(osTarget, osTargetArch, connectBackIP string, connectBackPort int, badChars []byte, prefix, suffix string) *ShellCodeBase {
	if connectBackIP == "" {
		connectBackIP = "localhost"
	}
	if connectBackPort == 0 {
		connectBackPort = 5555
	}

	return &ShellCodeBase{
		Target:       osTarget,
		Arch:         osTargetArch,
		IP:           connectBackIP,
		Port:         connectBackPort,
		BadChars:     string(badChars),
		Prefix:       prefix,
		Suffix:       suffix,
		Name:         "",
		TemplateVars: make(map[string]string),
	}
}

// GenShellCode 生成shellcode
func (s *ShellCodeBase) GenShellCode(code string) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}

	if code == "" {
		return "", fmt.Errorf("empty shellcode template")
	}

	// 添加默认模板变量
	s.TemplateVars["LOCALHOST"] = s.IP
	s.TemplateVars["LOCALPORT"] = fmt.Sprintf("%d", s.Port)

	// 替换所有模板变量
	for key, value := range s.TemplateVars {
		code = strings.ReplaceAll(code, "{{"+key+"}}", value)
	}

	return code, nil
}

// FormatShellCode 是GenShellCode的别名
func (s *ShellCodeBase) FormatShellCode(code string) (string, error) {
	return s.GenShellCode(code)
}

func (s *ShellCodeBase) MakeInline(payloads string) string {
	payloads = strings.ReplaceAll(payloads, "\t", " ")
	payloads = strings.ReplaceAll(payloads, "\r", " ")
	payloads = strings.ReplaceAll(payloads, "\n", " ")
	return payloads
}

// GetShellCode 获取shellcode
func (s *ShellCodeBase) GetShellCode(inline bool) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}

	// 基类中不实现具体逻辑，由子类实现
	return "", fmt.Errorf("GetShellCode not implemented in base class")
}

func (s *ShellCodeBase) Validate() error {
	if s.Target == "" {
		return fmt.Errorf("target OS is required")
	}
	if s.Arch == "" {
		return fmt.Errorf("target architecture is required")
	}
	if s.IP == "" {
		return fmt.Errorf("IP address is required")
	}
	if s.Port <= 0 || s.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", s.Port)
	}
	return nil
}
