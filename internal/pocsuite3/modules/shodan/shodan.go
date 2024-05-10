package shodan

type ShodanClient struct {
    BaseURL string
    Headers map[string]string
    Credits int
    Token   string
}

func NewShodanClient() *ShodanClient {
    return &ShodanClient{}
}

func (s *ShodanClient) Search() any {
    return ""
}

