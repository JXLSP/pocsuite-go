package fofa

import "net/http"

type FofaClient struct {
    BaseURL string
    Credist int
    Token   string
    Header  http.Header
}

func NewFofaClient() *FofaClient {
    return &FofaClient{}
}

func (fc *FofaClient) CheckToken() bool {
    return false
}

func (fc *FofaClient) Search(dork string, pages int, resource string) {}
