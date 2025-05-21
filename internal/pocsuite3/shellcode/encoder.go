package shellcode

import (
	"bytes"
	"fmt"
)

type Encoder struct {
	Payload []byte
}

type AlphanumericEncoder struct {
	AllowChars     []byte
	BufferRegister string
	Encoder
	Offset int
}

func NewAlphanumericEncoder() *AlphanumericEncoder {
	return &AlphanumericEncoder{
		BufferRegister: "eax",
		Offset:         0,
	}
}

func (a *AlphanumericEncoder) createAllowedChars(badChar []byte) []byte {
	// 生成所有可打印的字母数字字符
	allowedChars := make([]byte, 0)
	for c := byte(0x30); c <= byte(0x39); c++ { // 数字0-9
		if !bytes.Contains(badChar, []byte{c}) {
			allowedChars = append(allowedChars, c)
		}
	}
	for c := byte(0x41); c <= byte(0x5A); c++ { // 大写字母A-Z
		if !bytes.Contains(badChar, []byte{c}) {
			allowedChars = append(allowedChars, c)
		}
	}
	for c := byte(0x61); c <= byte(0x7A); c++ { // 小写字母a-z
		if !bytes.Contains(badChar, []byte{c}) {
			allowedChars = append(allowedChars, c)
		}
	}
	return allowedChars
}

func (a *AlphanumericEncoder) Encode(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	// 初始化编码器状态
	a.Payload = payload
	a.AllowChars = a.createAllowedChars(nil) // 默认不过滤任何字符

	// 生成解码器存根
	decoderStub := a.createDecoderStub([]byte(a.BufferRegister))

	// 编码每个字节
	encodedPayload := make([]byte, 0)
	for i := 0; i < len(payload); i += 4 {
		block := payload[i:min(i+4, len(payload))]
		encodedBlock := a.encodeByte(block)
		encodedPayload = append(encodedPayload, encodedBlock...)
	}

	// 组合最终的shellcode
	finalPayload := append(decoderStub, encodedPayload...)
	return finalPayload, nil
}

func (a *AlphanumericEncoder) createDecoderStub(reg []byte) []byte {
	// 生成解码器存根代码
	decoderPrefix := a.genDecoderPrefix(reg)
	
	// 基本的解码器框架
	decoderStub := []byte{
		0x25, 0x4A, 0x4D, 0x4E, 0x55, // and eax, 0x554E4D4A
		0x25, 0x35, 0x32, 0x31, 0x2A, // and eax, 0x2A313235
	}

	return append(decoderPrefix, decoderStub...)
}

func (a *AlphanumericEncoder) genDecoderPrefix(reg []byte) []byte {
	// 生成解码器前缀，用于设置寄存器初始状态
	prefix := []byte{
		0x54, // push esp
		0x58, // pop eax
	}

	if a.Offset > 0 {
		// 如果需要偏移，添加相应的指令
		prefix = append(prefix, []byte{
			0x05, byte(a.Offset & 0xff), byte((a.Offset >> 8) & 0xff),
			byte((a.Offset >> 16) & 0xff), byte((a.Offset >> 24) & 0xff), // add eax, offset
		}...)
	}

	return prefix
}

func (a *AlphanumericEncoder) encodeByte(block []byte) []byte {
	// 对4字节块进行编码
	encodedBlock := make([]byte, 0)

	// 使用AND操作清零寄存器
	encodedBlock = append(encodedBlock, []byte{
		0x25, 0x41, 0x41, 0x41, 0x41, // and eax, 0x41414141
	}...)

	// 使用SUB操作构造所需的值
	for _, b := range block {
		encodedBlock = append(encodedBlock, []byte{
			0x2D, b, 0x00, 0x00, 0x00, // sub eax, value
		}...)
	}

	return encodedBlock
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
