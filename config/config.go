package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

type Config struct {
	mu     sync.RWMutex
	path   string
	config map[string]map[string]string
}

func NewConfig(path string) (*Config, error) {
	config := &Config{
		path:   path,
		config: make(map[string]map[string]string),
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		if err := config.Load(); err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	}

	return config, nil
}

func (c *Config) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &c.config)
}

func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := yaml.Marshal(c.config)
	if err != nil {
		return err
	}

	return os.WriteFile(c.path, data, 0600)
}

func (c *Config) Get(section, key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if section, ok := c.config[section]; ok {
		value, ok := section[key]
		return value, ok
	}
	return "", false
}

func (c *Config) Set(section, key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.config[section]; !ok {
		c.config[section] = make(map[string]string)
	}
	c.config[section][key] = value

	return c.Save()
}

func (c *Config) GetSection(section string) (map[string]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sectionData, ok := c.config[section]
	if !ok {
		return nil, false
	}

	result := make(map[string]string)
	for k, v := range sectionData {
		result[k] = v
	}
	return result, true
}

func (c *Config) SetSection(section string, data map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config[section] = make(map[string]string)
	for k, v := range data {
		c.config[section][k] = v
	}

	return c.Save()
}

func (c *Config) Delete(section, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if section, ok := c.config[section]; ok {
		delete(section, key)
		return c.Save()
	}
	return nil
}

func (c *Config) DeleteSection(section string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.config, section)
	return c.Save()
}

func GetDefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".pocsuite-go.yaml"
	}
	return filepath.Join(home, ".pocsuite-go.yaml")
}
