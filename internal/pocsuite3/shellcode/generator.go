package shellcode

import (
	"fmt"
	"os"
)

type ShellGenerator struct {
	OS_TARGET      string
	OS_TARGET_ARCH string
	ShellcodesRoot string
	Utils          []string
}

type ShellCode2Hex struct {
	Shellcode  []byte
	Path       string
	Filename   string
	TargetOS   string
	TargetArch string
}

func (sc2 *ShellCode2Hex) MkDirs() error {
	if sc2.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	return os.MkdirAll(sc2.Path, 0755)
}
