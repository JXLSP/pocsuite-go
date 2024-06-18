package shellcode

import (
	"os"
	"path/filepath"
)

type ShellGenerator struct {
	OS_TARGET      string
	OS_TARGET_ARCH string
	Utils          []string
	ShellcodesRoot string
	UsePrecompiled bool
}

func NewShellGenerator(osTarget, osTargetArch string) *ShellGenerator {
	return &ShellGenerator{
		OS_TARGET:      osTarget,
		OS_TARGET_ARCH: osTargetArch,
		Utils:          []string{"nasm", "objdump"},
		ShellcodesRoot: func() string {
			dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
			return filepath.Join(dir, "data")
		}(),
		UsePrecompiled: false,
	}
}

func (sg *ShellGenerator) checkForSystemUtils() bool {
	return false
}

func (sg *ShellGenerator) makePath() string {
	return ""
}

func (sg *ShellGenerator) GetShellCode() string {
	return ""
}

type ShellCode2Hex struct {
	Shellcode   string
	TargetOS    string
	TargetArch  string
	DllInjFuncs any
	Filename    string
	Path        string
}

func NewShellCode2Hex() *ShellCode2Hex {
	return &ShellCode2Hex{}
}
