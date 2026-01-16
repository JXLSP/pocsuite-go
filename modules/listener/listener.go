package listener

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/seaung/pocsuite-go/config"
	"github.com/seaung/pocsuite-go/modules/interfaces"
)

func parsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", portStr)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port number out of range: %s", portStr)
	}
	return port, nil
}

type ListenerModule interface {
	interfaces.ListenerModule
}

type ListenerManager struct {
	clients     []*interfaces.Client
	clientsMu   sync.RWMutex
	listeners   map[string]ListenerModule
	listenersMu sync.RWMutex
	config      *config.Config
}

var (
	instance *ListenerManager
	once     sync.Once
)

func New(config *config.Config) *ListenerManager {
	once.Do(func() {
		instance = &ListenerManager{
			clients:   make([]*interfaces.Client, 0),
			listeners: make(map[string]ListenerModule),
			config:    config,
		}
	})
	return instance
}

func (lm *ListenerManager) Name() string {
	return "listener"
}

func (lm *ListenerManager) Init() error {
	return nil
}

func (lm *ListenerManager) IsAvailable() bool {
	return len(lm.listeners) > 0
}

func (lm *ListenerManager) AddClient(client *interfaces.Client) {
	lm.clientsMu.Lock()
	defer lm.clientsMu.Unlock()
	lm.clients = append(lm.clients, client)
}

func (lm *ListenerManager) RemoveClient(index int) error {
	lm.clientsMu.Lock()
	defer lm.clientsMu.Unlock()

	if index < 0 || index >= len(lm.clients) {
		return fmt.Errorf("invalid client index")
	}

	lm.clients = append(lm.clients[:index], lm.clients[index+1:]...)
	return nil
}

func (lm *ListenerManager) ListClients() []interfaces.Client {
	lm.clientsMu.RLock()
	defer lm.clientsMu.RUnlock()

	clients := make([]interfaces.Client, len(lm.clients))
	for i, client := range lm.clients {
		clients[i] = *client
	}
	return clients
}

func (lm *ListenerManager) GetClient(index int) (*interfaces.Client, error) {
	lm.clientsMu.RLock()
	defer lm.clientsMu.RUnlock()

	if index < 0 || index >= len(lm.clients) {
		return nil, fmt.Errorf("invalid client index")
	}
	return lm.clients[index], nil
}

func (lm *ListenerManager) RegisterListener(name string, listener ListenerModule) {
	lm.listenersMu.Lock()
	defer lm.listenersMu.Unlock()
	lm.listeners[name] = listener
}

func (lm *ListenerManager) GetListener(name string) (ListenerModule, error) {
	lm.listenersMu.RLock()
	defer lm.listenersMu.RUnlock()

	listener, ok := lm.listeners[name]
	if !ok {
		return nil, fmt.Errorf("listener %s not found", name)
	}
	return listener, nil
}

func (lm *ListenerManager) StartListener(name string) error {
	listener, err := lm.GetListener(name)
	if err != nil {
		return err
	}
	return listener.Start()
}

func (lm *ListenerManager) StopListener(name string) error {
	listener, err := lm.GetListener(name)
	if err != nil {
		return err
	}
	return listener.Stop()
}

func (lm *ListenerManager) StopAll() {
	lm.listenersMu.RLock()
	defer lm.listenersMu.RUnlock()

	for _, listener := range lm.listeners {
		listener.Stop()
	}
}

func (lm *ListenerManager) CloseAllClients() {
	lm.clientsMu.Lock()
	defer lm.clientsMu.Unlock()

	for _, client := range lm.clients {
		if client.Conn != nil {
			if conn, ok := client.Conn.(net.Conn); ok {
				conn.Close()
			}
		}
	}
	lm.clients = lm.clients[:0]
}

func (lm *ListenerManager) SendCommand(client *interfaces.Client, command string) error {
	if client == nil || client.Conn == nil {
		return fmt.Errorf("invalid client")
	}

	conn, ok := client.Conn.(net.Conn)
	if !ok {
		return fmt.Errorf("invalid connection type")
	}

	_, err := conn.Write([]byte(command + "\n"))
	return err
}

func (lm *ListenerManager) ReadResponse(client *interfaces.Client, timeout time.Duration) (string, error) {
	if client == nil || client.Conn == nil {
		return "", fmt.Errorf("invalid client")
	}

	conn, ok := client.Conn.(net.Conn)
	if !ok {
		return "", fmt.Errorf("invalid connection type")
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}
