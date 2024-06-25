package shellcode

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
	return &AlphanumericEncoder{}
}

func (a *AlphanumericEncoder) createAllowedChars(badChar []byte) []byte {
	return []byte{}
}

func (a *AlphanumericEncoder) Encode(payload []byte) {}

func (a *AlphanumericEncoder) createDecoderStub(reg []byte) {}

func (a *AlphanumericEncoder) genDecoderPrefix(reg []byte) {}

func (a *AlphanumericEncoder) encodeByte(block []byte) {}
