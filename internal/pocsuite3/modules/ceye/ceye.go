package ceye

type Ceye struct {
    Token string
    url string
}

func NewCeyeClient() *Ceye {
    return &Ceye{}
}

func (c *Ceye) tokenIsAvaliable() bool {
    return false
}

func (c *Ceye) checkAccount() bool {
    return c.tokenIsAvaliable()
}

func (c *Ceye) checkToken() bool {
    return false
}

func (c *Ceye) GetSubdomain() string {
    return ""
}

func (c *Ceye) BuildRequest() map[string]any {
    return map[string]any{"token": "xxx"}
}

func (c *Ceye) ExtrctRequest() bool {
    return false
}

func (c *Ceye) VerifyRequest(flag any, itype string) bool {
    return false
}
