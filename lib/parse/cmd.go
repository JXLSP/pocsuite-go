package parse

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ShowVersion       bool
	UpdateAll         bool
	New               bool
	Verbose           int
	URLs              []string
	URLFile           string
	Ports             string
	SkipTargetPort    bool
	POC               []string
	POCKeyword        string
	ConfigFile        string
	POCList           bool
	Mode              string // verify, attack, shell
	Cookie            string
	Host              string
	Referer           string
	UserAgent         string
	Proxy             string
	ProxyCred         string
	Timeout           float64
	Retry             int
	Delay             string
	Headers           string
	HTTPDebug         int
	SessionReuse      bool
	SessionReuseNum   int
	CEyeToken         string
	OOBServer         string
	OOBToken          string
	SeebugToken       string
	ZoomEyeToken      string
	ShodanToken       string
	FofaUser          string
	FofaToken         string
	QuakeToken        string
	HunterToken       string
	CensysUID         string
	CensysSecret      string
	Dork              string
	DorkZoomEye       string
	DorkShodan        string
	DorkFofa          string
	DorkQuake         string
	DorkHunter        string
	DorkCensys        string
	MaxPage           int
	PageSize          int
	SearchType        string
	VulKeyword        string
	SSVID             string
	ConnectBackHost   string
	ConnectBackPort   string
	EnableTLSListener bool
	Comparison        bool
	DorkB64           bool
	OutputPath        string
	Plugins           string
	POCsPath          string
	Threads           int
	Batch             string
	CheckRequires     bool
	Quiet             bool
	PPT               bool
	PCAP              bool
	Rule              bool
	RuleReq           bool
	RuleFilename      string
	NoCheck           bool
	DockerStart       bool
	DockerPort        []string
	DockerVolume      []string
	DockerEnv         []string
	DockerOnly        bool
	DingtalkToken     string
	DingtalkSecret    string
	WxWorkKey         string
	ShowOptions       bool
	DIYOptions        map[string]string
}

type Parser struct {
	flagSet *flag.FlagSet
	config  *Config
}

func NewParser() *Parser {
	return &Parser{
		flagSet: flag.NewFlagSet("pocsuite", flag.ExitOnError),
		config:  &Config{DIYOptions: make(map[string]string)},
	}
}

func (p *Parser) Parse(args []string) (*Config, error) {
	if len(args) == 0 {
		args = os.Args[1:]
	}

	p.flagSet.BoolVar(&p.config.ShowVersion, "version", false, "Show program's version number and exit")
	p.flagSet.BoolVar(&p.config.UpdateAll, "update", false, "Update Pocsuite3")
	p.flagSet.BoolVar(&p.config.New, "new", false, "Create a PoC template")
	p.flagSet.IntVar(&p.config.Verbose, "v", 1, "Verbosity level: 0-6 (default 1)")

	p.flagSet.Func("u", "Target URL/CIDR (e.g. \"http://www.site.com/vuln.php?id=1\")", func(s string) error {
		p.config.URLs = append(p.config.URLs, s)
		return nil
	})
	p.flagSet.StringVar(&p.config.URLFile, "f", "", "Scan multiple targets given in a textual file (one per line)")
	p.flagSet.StringVar(&p.config.Ports, "p", "", "add additional port to each target ([proto:]port, e.g. 8080,https:10000)")
	p.flagSet.BoolVar(&p.config.SkipTargetPort, "s", false, "Skip target's port, only use additional port")
	p.flagSet.Func("r", "Load PoC file from local or remote from seebug website", func(s string) error {
		p.config.POC = append(p.config.POC, s)
		return nil
	})
	p.flagSet.StringVar(&p.config.POCKeyword, "k", "", "Filter PoC by keyword, e.g. ecshop")
	p.flagSet.StringVar(&p.config.ConfigFile, "c", "", "Load options from a configuration INI file")
	p.flagSet.BoolVar(&p.config.POCList, "l", false, "Show all PoC file from local")

	mode := "verify"
	p.flagSet.StringVar(&mode, "verify", "verify", "Run poc with verify mode")
	p.flagSet.StringVar(&mode, "attack", "attack", "Run poc with attack mode")
	p.flagSet.StringVar(&mode, "shell", "shell", "Run poc with shell mode")
	p.config.Mode = mode

	p.flagSet.StringVar(&p.config.Cookie, "cookie", "", "HTTP Cookie header value")
	p.flagSet.StringVar(&p.config.Host, "host", "", "HTTP Host header value")
	p.flagSet.StringVar(&p.config.Referer, "referer", "", "HTTP Referer header value")
	p.flagSet.StringVar(&p.config.UserAgent, "user-agent", "", "HTTP User-Agent header value (default random)")
	p.flagSet.StringVar(&p.config.Proxy, "proxy", "", "Use a proxy to connect to the target URL (protocol://host:port)")
	p.flagSet.StringVar(&p.config.ProxyCred, "proxy-cred", "", "Proxy authentication credentials (name:password)")
	p.flagSet.Float64Var(&p.config.Timeout, "timeout", 10, "Seconds to wait before timeout connection (default 10)")
	p.flagSet.IntVar(&p.config.Retry, "retry", 0, "Time out retrials times (default 0)")
	p.flagSet.StringVar(&p.config.Delay, "delay", "", "Delay between two request of one thread")
	p.flagSet.StringVar(&p.config.Headers, "headers", "", "Extra headers (e.g. \"key1: value1\\nkey2: value2\")")
	p.flagSet.IntVar(&p.config.HTTPDebug, "http-debug", 0, "HTTP debug level (default 0)")
	p.flagSet.BoolVar(&p.config.SessionReuse, "session-reuse", false, "Enable requests session reuse")
	p.flagSet.IntVar(&p.config.SessionReuseNum, "session-reuse-num", 10, "Requests session reuse number")

	p.flagSet.StringVar(&p.config.CEyeToken, "ceye-token", "", "CEye token")
	p.flagSet.StringVar(&p.config.OOBServer, "oob-server", "interact.sh", "Interactsh server to use (default \"interact.sh\")")
	p.flagSet.StringVar(&p.config.OOBToken, "oob-token", "", "Authentication token to connect protected interactsh server")
	p.flagSet.StringVar(&p.config.SeebugToken, "seebug-token", "", "Seebug token")
	p.flagSet.StringVar(&p.config.ZoomEyeToken, "zoomeye-token", "", "ZoomEye token")
	p.flagSet.StringVar(&p.config.ShodanToken, "shodan-token", "", "Shodan token")
	p.flagSet.StringVar(&p.config.FofaUser, "fofa-user", "", "Fofa user")
	p.flagSet.StringVar(&p.config.FofaToken, "fofa-token", "", "Fofa token")
	p.flagSet.StringVar(&p.config.QuakeToken, "quake-token", "", "Quake token")
	p.flagSet.StringVar(&p.config.HunterToken, "hunter-token", "", "Hunter token")
	p.flagSet.StringVar(&p.config.CensysUID, "censys-uid", "", "Censys uid")
	p.flagSet.StringVar(&p.config.CensysSecret, "censys-secret", "", "Censys secret")

	p.flagSet.StringVar(&p.config.Dork, "dork", "", "Zoomeye dork used for search")
	p.flagSet.StringVar(&p.config.DorkZoomEye, "dork-zoomeye", "", "Zoomeye dork used for search")
	p.flagSet.StringVar(&p.config.DorkShodan, "dork-shodan", "", "Shodan dork used for search")
	p.flagSet.StringVar(&p.config.DorkFofa, "dork-fofa", "", "Fofa dork used for search")
	p.flagSet.StringVar(&p.config.DorkQuake, "dork-quake", "", "Quake dork used for search")
	p.flagSet.StringVar(&p.config.DorkHunter, "dork-hunter", "", "Hunter dork used for search")
	p.flagSet.StringVar(&p.config.DorkCensys, "dork-censys", "", "Censys dork used for search")
	p.flagSet.IntVar(&p.config.MaxPage, "max-page", 1, "Max page used in search API")
	p.flagSet.IntVar(&p.config.PageSize, "page-size", 20, "Page size used in search API")
	p.flagSet.StringVar(&p.config.SearchType, "search-type", "v4", "search type used in search API, v4,v6 and web")
	p.flagSet.StringVar(&p.config.VulKeyword, "vul-keyword", "", "Seebug keyword used for search")
	p.flagSet.StringVar(&p.config.SSVID, "ssv-id", "", "Seebug SSVID number for target PoC")
	p.flagSet.StringVar(&p.config.ConnectBackHost, "lhost", "", "Connect back host for target PoC in shell mode")
	p.flagSet.StringVar(&p.config.ConnectBackPort, "lport", "", "Connect back port for target PoC in shell mode")
	p.flagSet.BoolVar(&p.config.EnableTLSListener, "tls", false, "Enable TLS listener in shell mode")
	p.flagSet.BoolVar(&p.config.Comparison, "comparison", false, "Compare popular web search engines")
	p.flagSet.BoolVar(&p.config.DorkB64, "dork-b64", false, "Whether dork is in base64 format")

	p.flagSet.StringVar(&p.config.OutputPath, "output", "", "Output file to write (JSON Lines format)")
	p.flagSet.StringVar(&p.config.Plugins, "plugins", "", "Load plugins to execute")
	p.flagSet.StringVar(&p.config.POCsPath, "pocs-path", "", "User defined poc scripts path")
	p.flagSet.IntVar(&p.config.Threads, "threads", 150, "Max number of concurrent network requests (default 150)")
	p.flagSet.StringVar(&p.config.Batch, "batch", "", "Automatically choose default choice without asking")
	p.flagSet.BoolVar(&p.config.CheckRequires, "requires", false, "Check install_requires")
	p.flagSet.BoolVar(&p.config.Quiet, "quiet", false, "Activate quiet mode, working without logger")
	p.flagSet.BoolVar(&p.config.PPT, "ppt", false, "Hidden sensitive information when published to the network")
	p.flagSet.BoolVar(&p.config.PCAP, "pcap", false, "use scapy capture flow")
	p.flagSet.BoolVar(&p.config.Rule, "rule", false, "export suricata rules, default export request and response")
	p.flagSet.BoolVar(&p.config.RuleReq, "rule-req", false, "only export request rule")
	p.flagSet.StringVar(&p.config.RuleFilename, "rule-filename", "", "Specify the name of the export rule file")
	p.flagSet.BoolVar(&p.config.NoCheck, "no-check", false, "Disable URL protocol correction and honeypot check")

	p.flagSet.BoolVar(&p.config.DockerStart, "docker-start", false, "Run the docker for PoC")
	p.flagSet.Func("docker-port", "Publish a container's port(s) to the host", func(s string) error {
		p.config.DockerPort = append(p.config.DockerPort, s)
		return nil
	})
	p.flagSet.Func("docker-volume", "Bind mount a volume", func(s string) error {
		p.config.DockerVolume = append(p.config.DockerVolume, s)
		return nil
	})
	p.flagSet.Func("docker-env", "Set environment variables", func(s string) error {
		p.config.DockerEnv = append(p.config.DockerEnv, s)
		return nil
	})
	p.flagSet.BoolVar(&p.config.DockerOnly, "docker-only", false, "Only run docker environment")

	p.flagSet.StringVar(&p.config.DingtalkToken, "dingtalk-token", "", "Dingtalk access token")
	p.flagSet.StringVar(&p.config.DingtalkSecret, "dingtalk-secret", "", "Dingtalk secret")
	p.flagSet.StringVar(&p.config.WxWorkKey, "wx-work-key", "", "Weixin Work key")

	p.flagSet.BoolVar(&p.config.ShowOptions, "options", false, "Show all definition options")

	err := p.flagSet.Parse(args)
	if err != nil {
		return nil, fmt.Errorf("failed to parse command line arguments: %w", err)
	}

	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(arg[2:], "=", 2)
			key := parts[0]
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}
			p.config.DIYOptions[key] = value
		}
	}

	return p.config, nil
}

func (p *Parser) GetConfig() *Config {
	return p.config
}

func (p *Parser) PrintUsage() {
	fmt.Println("Pocsuite3 - A powerful POC testing framework")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  pocsuite [options]")
	fmt.Println()
	fmt.Println("Options:")
	p.flagSet.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pocsuite -u http://example.com -r poc.py")
	fmt.Println("  pocsuite -f targets.txt -r poc.py --verify")
	fmt.Println("  pocsuite -u http://example.com -r poc.py --attack")
}

func (c *Config) Validate() error {
	if len(c.URLs) == 0 && c.URLFile == "" && c.Dork == "" && c.DorkZoomEye == "" &&
		c.DorkShodan == "" && c.DorkFofa == "" && c.DorkQuake == "" && c.DorkHunter == "" &&
		c.DorkCensys == "" {
		return fmt.Errorf("at least one target option must be specified (use -u, -f, or --dork)")
	}

	if c.Mode != "verify" && c.Mode != "attack" && c.Mode != "shell" {
		return fmt.Errorf("invalid mode: %s (must be verify, attack, or shell)", c.Mode)
	}

	if c.Threads < 1 {
		return fmt.Errorf("threads must be at least 1")
	}

	if c.Timeout < 0 {
		return fmt.Errorf("timeout must be non-negative")
	}

	if c.Verbose < 0 || c.Verbose > 6 {
		return fmt.Errorf("verbose level must be between 0 and 6")
	}

	return nil
}

func (c *Config) HasTargets() bool {
	return len(c.URLs) > 0 || c.URLFile != "" || c.Dork != "" || c.DorkZoomEye != "" ||
		c.DorkShodan != "" || c.DorkFofa != "" || c.DorkQuake != "" || c.DorkHunter != "" ||
		c.DorkCensys != ""
}

func (c *Config) HasPOCs() bool {
	return len(c.POC) > 0 || c.POCKeyword != "" || c.SSVID != ""
}

func (c *Config) IsVerifyMode() bool {
	return c.Mode == "verify"
}

func (c *Config) IsAttackMode() bool {
	return c.Mode == "attack"
}

func (c *Config) IsShellMode() bool {
	return c.Mode == "shell"
}

func (c *Config) HasProxy() bool {
	return c.Proxy != ""
}

func (c *Config) HasAuthentication() bool {
	return c.CEyeToken != "" || c.SeebugToken != "" || c.ZoomEyeToken != "" ||
		c.ShodanToken != "" || c.FofaToken != "" || c.QuakeToken != "" ||
		c.HunterToken != "" || c.CensysUID != ""
}

func (c *Config) GetDork() string {
	if c.Dork != "" {
		return c.Dork
	}
	if c.DorkZoomEye != "" {
		return c.DorkZoomEye
	}
	if c.DorkShodan != "" {
		return c.DorkShodan
	}
	if c.DorkFofa != "" {
		return c.DorkFofa
	}
	if c.DorkQuake != "" {
		return c.DorkQuake
	}
	if c.DorkHunter != "" {
		return c.DorkHunter
	}
	if c.DorkCensys != "" {
		return c.DorkCensys
	}
	return ""
}

func (c *Config) GetConnectBackAddress() string {
	if c.ConnectBackHost != "" && c.ConnectBackPort != "" {
		return fmt.Sprintf("%s:%s", c.ConnectBackHost, c.ConnectBackPort)
	}
	return ""
}
