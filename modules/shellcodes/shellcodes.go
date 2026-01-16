package shellcodes

import (
	"errors"
	"fmt"
)

type OS string

const (
	Windows OS = "windows"
	Linux   OS = "linux"
)

type Arch string

const (
	Arch32 Arch = "32bit"
	Arch64 Arch = "64bit"
)

type ShellcodeType string

const (
	Bind    ShellcodeType = "bind_tcp"
	Reverse ShellcodeType = "reverse_tcp"
)

type WebShellType string

const (
	JSP    WebShellType = "jsp"
	ASPX   WebShellType = "aspx"
	PHP    WebShellType = "php"
	Python WebShellType = "python"
)

type OSShellcodes struct {
	osTarget       OS
	osArch         Arch
	shellcodesPath string
}

type WebShell struct {
	webShellType WebShellType
}

func NewOSShellcodes(osTarget OS, osArch Arch) (*OSShellcodes, error) {
	if osTarget != Windows && osTarget != Linux {
		return nil, errors.New("invalid OS target")
	}
	if osArch != Arch32 && osArch != Arch64 {
		return nil, errors.New("invalid architecture")
	}

	return &OSShellcodes{
		osTarget:       osTarget,
		osArch:         osArch,
		shellcodesPath: "./data",
	}, nil
}

func NewWebShell(webShellType WebShellType) (*WebShell, error) {
	switch webShellType {
	case JSP, ASPX, PHP, Python:
		return &WebShell{
			webShellType: webShellType,
		}, nil
	default:
		return nil, errors.New("invalid webshell type")
	}
}

func (os *OSShellcodes) CreateShellcode(
	shellcodeType ShellcodeType,
	connectbackIP string,
	connectbackPort int,
	encoding string,
) ([]byte, error) {
	if shellcodeType != Bind && shellcodeType != Reverse {
		return nil, errors.New("invalid shellcode type")
	}

	if connectbackPort < 0 || connectbackPort > 65535 {
		return nil, errors.New("invalid port number")
	}

	generator := NewShellGenerator(os.osTarget, os.osArch, os.shellcodesPath)

	shellcode, err := generator.Generate(shellcodeType, connectbackIP, connectbackPort, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shellcode: %w", err)
	}

	return shellcode, nil
}

func (os *OSShellcodes) CreateExe(
	shellcodeType ShellcodeType,
	connectbackIP string,
	connectbackPort int,
	filename string,
) ([]byte, error) {
	shellcode, err := os.CreateShellcode(shellcodeType, connectbackIP, connectbackPort, "")
	if err != nil {
		return nil, err
	}

	builder := NewExeBuilder(os.osTarget, os.osArch)
	exeData, err := builder.Build(shellcode)
	if err != nil {
		return nil, fmt.Errorf("failed to build exe: %w", err)
	}

	return exeData, nil
}

func (ws *WebShell) CreateWebShell(password string) (string, error) {
	generator := NewWebShellGenerator()

	switch ws.webShellType {
	case JSP:
		return generator.GenerateJSP(password)
	case ASPX:
		return generator.GenerateASPX(password)
	case PHP:
		return generator.GeneratePHP(password)
	case Python:
		return generator.GeneratePython(password)
	default:
		return "", errors.New("unsupported webshell type")
	}
}

func (os *OSShellcodes) GetOSTarget() OS {
	return os.osTarget
}

func (os *OSShellcodes) GetArch() Arch {
	return os.osArch
}

func (ws *WebShell) GetWebShellType() WebShellType {
	return ws.webShellType
}
