package helper

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"syscall"
)

func GetHostIPV6(dest string) string {
	if dest == "" {
		dest = "2001:db8::"
	}

	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return ""
	}
	defer syscall.Close(fd)

	ip := net.ParseIP(dest)
	if ip == nil || ip.To16() == nil {
		addrs, err := net.LookupIP(dest)
		if err != nil || len(addrs) == 0 {
			return ""
		}

		for _, addr := range addrs {
			if addr.To16() != nil && addr.To4() == nil {
				ip = addr
				break
			}
		}

		if ip == nil || ip.To16() == nil {
			return ""
		}
	}

	var ipv6addr [16]byte
	copy(ipv6addr[:], ip.To16())

	saddr := syscall.SockaddrInet6{
		Port:   1027,
		Addr:   ipv6addr,
		ZoneId: 0,
	}

	if err := syscall.Connect(fd, &saddr); err != nil {
		return ""
	}

	name, err := syscall.Getsockname(fd)
	if err != nil {
		return ""
	}

	if sa, ok := name.(*syscall.SockaddrInet6); ok {
		ip := net.IP(sa.Addr[:])
		return ip.String()
	}

	return ""
}

func EncodingBashPayload(cmd string) string {
	encodedCmd := base64.StdEncoding.EncodeToString([]byte(cmd))
	return fmt.Sprintf("bash -c '{echo,%s}|{base64,-d}|{bash,-i}'", encodedCmd)
}

func EncodingPowerShellPayload(powershell string) string {
	command := "powershell -NonI -W Hidden -NoP -Exec Bypass -Enc "

	var encodedBytes []byte
	for _, char := range powershell {
		encodedBytes = append(encodedBytes, 0x00)
		encodedBytes = append(encodedBytes, byte(char))
	}
	encodedBytes = append(encodedBytes, 0x00)

	encodedStr := base64.StdEncoding.EncodeToString(encodedBytes)

	return command + encodedStr
}

func ExecuteCommand(cmd string, rawData bool) ([]byte, error) {
	parts, err := SplitCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("error splitting command: %v", err)
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	execCmd := exec.Command(parts[0], parts[1:]...)

	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %v", err)
	}

	execCmd.Stderr = execCmd.Stdout

	if err := execCmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting command: %v", err)
	}

	var outData []byte
	buf := make([]byte, 1024)
	for {
		n, err := stdoutPipe.Read(buf)
		if n > 0 {
			outData = append(outData, buf[:n]...)
		}
		if err != nil {
			if err != io.EOF {
				return outData, fmt.Errorf("error reading output: %v", err)
			}
			break
		}
	}

	if err := execCmd.Wait(); err != nil {
		return outData, fmt.Errorf("command execution failed: %v", err)
	}

	var splitData [][]byte
	if runtime.GOOS == "windows" {
		splitData = bytes.Split(outData, []byte("\r\n\r\n"))
	} else {
		splitData = bytes.Split(outData, []byte("\n\n"))
	}

	if !rawData {
		for i, data := range splitData {
			str := string(data)
			splitData[i] = []byte(str)
		}
	}

	result := bytes.Join(splitData, []byte(""))
	return result, nil
}

func SplitCommand(cmd string) ([]string, error) {
	var parts []string
	var current string
	inQuotes := false
	quoteChar := '"'

	for _, char := range cmd {
		switch {
		case char == '"' || char == '\\':
			if inQuotes && char == quoteChar {
				inQuotes = false
			} else if !inQuotes {
				inQuotes = true
				quoteChar = char
			} else {
				current += string(char)
			}
		case char == ' ':
			if inQuotes {
				current += string(char)
			} else if current != "" {
				parts = append(parts, current)
				current = ""
			}
		default:
			current += string(char)
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	if inQuotes {
		return nil, fmt.Errorf("unclosed quotes in command")
	}

	return parts, nil
}
