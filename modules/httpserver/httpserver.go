package httpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/seaung/pocsuite-go/config"
)

type BaseRequestHandler struct{}

func (h *BaseRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.FileServer(http.Dir(".")).ServeHTTP(w, r)
}

type HTTPServer struct {
	bindIP         string
	bindPort       int
	isIPv6         bool
	useHTTPS       bool
	scheme         string
	certFile       string
	serverLocked   bool
	serverStarted  bool
	requestHandler http.Handler
	hostIP         string
	url            string
	httpd          *http.Server
	flag           *sync.Cond
	running        bool
	mu             sync.Mutex
	config         *config.Config
}

var (
	instance *HTTPServer
	once     sync.Once
)

func New(config *config.Config) *HTTPServer {
	once.Do(func() {
		instance = &HTTPServer{
			bindIP:         "0.0.0.0",
			bindPort:       6666,
			isIPv6:         false,
			useHTTPS:       false,
			scheme:         "http",
			serverLocked:   false,
			serverStarted:  false,
			requestHandler: &BaseRequestHandler{},
			running:        true,
			config:         config,
		}
		instance.flag = sync.NewCond(&instance.mu)
	})
	return instance
}

func (h *HTTPServer) Name() string {
	return "httpserver"
}

func (h *HTTPServer) Init() error {
	if bindIP, ok := h.config.Get("HTTPServer", "bind_ip"); ok {
		h.bindIP = bindIP
	}
	if bindPort, ok := h.config.Get("HTTPServer", "bind_port"); ok {
		if port, err := parsePort(bindPort); err == nil {
			h.bindPort = port
		}
	}
	if useHTTPS, ok := h.config.Get("HTTPServer", "use_https"); ok {
		h.useHTTPS = useHTTPS == "true"
	}

	if strings.Contains(h.bindIP, ":") {
		h.isIPv6 = true
		h.hostIP = getHostIPv6()
		if h.hostIP == "" {
			return fmt.Errorf("your machine may not support ipv6")
		}
	} else {
		h.isIPv6 = false
		h.hostIP = getHostIP()
	}

	if h.useHTTPS {
		h.scheme = "https"
	} else {
		h.scheme = "http"
	}

	if h.isIPv6 {
		h.url = fmt.Sprintf("%s://[%s]:%d", h.scheme, h.bindIP, h.bindPort)
	} else {
		h.url = fmt.Sprintf("%s://%s:%d", h.scheme, h.bindIP, h.bindPort)
	}

	return nil
}

func (h *HTTPServer) IsAvailable() bool {
	return h.serverStarted
}

func (h *HTTPServer) Start(port int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if port > 0 {
		h.bindPort = port
		if h.isIPv6 {
			h.url = fmt.Sprintf("%s://[%s]:%d", h.scheme, h.bindIP, h.bindPort)
		} else {
			h.url = fmt.Sprintf("%s://%s:%d", h.scheme, h.bindIP, h.bindPort)
		}
	}

	if h.serverLocked {
		return fmt.Errorf("httpd server has been started on %s", h.url)
	}

	checkIP := h.hostIP
	if h.bindIP == "0.0.0.0" {
		checkIP = "127.0.0.1"
	} else if h.bindIP == "::" {
		checkIP = "::1"
	}

	if !isPortAvailable(checkIP, h.bindPort) {
		return fmt.Errorf("port %d has been occupied, start httpd server failed", h.bindPort)
	}

	h.serverLocked = true
	h.serverStarted = true

	go h.run()

	return nil
}

func (h *HTTPServer) run() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", h.bindIP, h.bindPort))
	if err != nil {
		fmt.Printf("Failed to start httpd: %v\n", err)
		return
	}

	h.mu.Lock()
	h.httpd = &http.Server{
		Handler: h.requestHandler,
	}
	h.mu.Unlock()

	if h.useHTTPS {
		if h.certFile != "" {
			cert, err := tls.LoadX509KeyPair(h.certFile, h.certFile)
			if err != nil {
				fmt.Printf("Failed to load certificate: %v\n", err)
				listener.Close()
				return
			}
			h.mu.Lock()
			h.httpd.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
			h.mu.Unlock()
			listener = tls.NewListener(listener, h.httpd.TLSConfig)
		} else {
			fmt.Println("You must provide certfile to use https")
			listener.Close()
			return
		}
	}

	fmt.Printf("Starting httpd on %s\n", h.url)

	if err := h.httpd.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Printf("Httpd server error: %v\n", err)
	}

	h.mu.Lock()
	h.serverStarted = false
	h.serverLocked = false
	h.mu.Unlock()
	fmt.Printf("Stop httpd server on %s\n", h.url)
}

func (h *HTTPServer) Pause() {
	h.mu.Lock()
	defer h.mu.Unlock()
}

func (h *HTTPServer) Resume() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.flag.Broadcast()
}

func (h *HTTPServer) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.running = false
	h.flag.Broadcast()

	if h.httpd != nil {
		if err := h.httpd.Shutdown(context.Background()); err != nil {
			return err
		}
	}

	h.serverStarted = false
	h.serverLocked = false
	return nil
}

func (h *HTTPServer) GetURL() string {
	return h.url
}

func (h *HTTPServer) GetHostIP() string {
	return h.hostIP
}

func (h *HTTPServer) SetBindIP(ip string) {
	h.bindIP = ip
}

func (h *HTTPServer) SetBindPort(port int) {
	h.bindPort = port
}

func (h *HTTPServer) SetUseHTTPS(useHTTPS bool) {
	h.useHTTPS = useHTTPS
	if useHTTPS {
		h.scheme = "https"
	} else {
		h.scheme = "http"
	}
}

func (h *HTTPServer) SetCertFile(certFile string) {
	h.certFile = certFile
}

func (h *HTTPServer) SetRequestHandler(handler http.Handler) {
	h.requestHandler = handler
}

func parsePort(portStr string) (int, error) {
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	return port, err
}

func getHostIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return "127.0.0.1"
}

func getHostIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() == nil {
				return ipnet.IP.String()
			}
		}
	}

	return "::1"
}

func isPortAvailable(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}
