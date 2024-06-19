package shellcode

import (
	"strconv"
	"strings"
)

type ShellCoder interface {
    GenShellCode(code string) string
    MakeInline(payloads string) string
    GetShellCode() string
}

type ShellCodeBase struct {
    Target      string
    Arch        string
    IP          string
    Port        int
    Name        string
    Prefix      string
    Suffix      string
    BadChars    string
}

func NewShellCodeBase(osTarget, osTargetArch, connectBackIP string, connectBackPort int, badChars []byte, prefix, suffix string) *ShellCodeBase {
    return &ShellCodeBase{}
}

func (s *ShellCodeBase) GenShellCode(code string) string {
    if code != "" {
        code = strings.ReplaceAll(code, "{{LOCALHOST}}", s.IP)
        code = strings.ReplaceAll(code, "{{LOCALPORT}}", strconv.Itoa(s.Port))
    }
    return code
}

func (s *ShellCodeBase) MakeInline(payloads string) string {
    payloads = strings.ReplaceAll(payloads, "\t", " ")
    payloads = strings.ReplaceAll(payloads, "\r", " ")
    payloads = strings.ReplaceAll(payloads, "\n", " ")
    return payloads
}

func (s *ShellCodeBase) GetShellCode() string {
    return ""
}
