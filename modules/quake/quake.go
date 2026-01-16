package quake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/seaung/pocsuite-go/config"
)

const (
	apiURL = "https://quake.360.cn/api/v3"
)

type Quake struct {
	client *http.Client
	token  string
	config *config.Config
}

func New(config *config.Config) *Quake {
	return &Quake{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (q *Quake) Name() string {
	return "quake"
}

func (q *Quake) Init() error {
	if token, ok := q.config.Get("Quake", "token"); ok {
		q.token = token
	}

	if q.token == "" {
		return fmt.Errorf("quake token not configured")
	}

	return nil
}

func (q *Quake) IsAvailable() bool {
	if q.token == "" {
		return false
	}

	apiURL := fmt.Sprintf("%s/user/info", apiURL)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("X-QuakeToken", q.token)
	req.Header.Set("User-Agent", "curl/7.80.0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := q.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	if code, ok := result["code"].(float64); ok {
		return int(code) == 0
	}

	return false
}

func (q *Quake) Search(dork string, pages int, resource string) ([]string, error) {
	if !q.IsAvailable() {
		return nil, fmt.Errorf("quake token is not available")
	}

	var results []string

	for page := 1; page <= pages; page++ {
		time.Sleep(1 * time.Second)

		requestBody := map[string]interface{}{
			"query":        dork,
			"size":         10,
			"ignore_cache": false,
			"start":        page,
		}

		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}

		searchURL := fmt.Sprintf("%s/search/quake_service", apiURL)
		req, err := http.NewRequest("POST", searchURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("X-QuakeToken", q.token)
		req.Header.Set("User-Agent", "curl/7.80.0")
		req.Header.Set("Content-Type", "application/json")

		resp, err := q.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
		}

		var response struct {
			Code int `json:"code"`
			Data []struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			} `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		if response.Code != 0 {
			return nil, fmt.Errorf("api returned error code: %d", response.Code)
		}

		for _, match := range response.Data {
			ip := match.IP

			if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
				ip = fmt.Sprintf("[%s]", ip)
			}

			if resource == "host" {
				target := fmt.Sprintf("%s:%d", ip, match.Port)
				results = append(results, target)
			} else {
				target := fmt.Sprintf("http://%s:%d", ip, match.Port)
				results = append(results, target)
			}
		}
	}

	return results, nil
}

func (q *Quake) SetToken(token string) error {
	q.token = token

	if err := q.config.Set("Quake", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
