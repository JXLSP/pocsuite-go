package interfaces

type Module interface {
	Name() string
	Init() error
	IsAvailable() bool
}

type Searcher interface {
	Module
	Search(dork string, pages int, resource string) ([]string, error)
}

type OASTService interface {
	Module
	GetDomain() string
	GetURL() string
	CheckInteraction() bool
}

type VulnerabilityDB interface {
	Module
	SearchVuln(cveID string) (map[string]interface{}, error)
}

type HTTPServer interface {
	Module
	Start(port int) error
	Stop() error
	GetURL() string
}

type ListenerModule interface {
	Module
	Start() error
	Stop() error
	ListClients() []Client
	GetClient(index int) (*Client, error)
}

type Client struct {
	Conn    interface{}
	Address interface{}
}

type Spider interface {
	Module
	Crawl(url string, depth int) ([]string, error)
}

type Shellcodes interface {
	Module
	CreateOSShellcode(osTarget string, arch string, shellcodeType string, connectbackIP string, connectbackPort int, encoding string) ([]byte, error)
	CreateExe(osTarget string, arch string, shellcodeType string, connectbackIP string, connectbackPort int, filename string) ([]byte, error)
	CreateWebShell(webShellType string, password string) (string, error)
}
