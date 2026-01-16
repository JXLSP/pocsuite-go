package zoomeye

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/seaung/pocsuite-go/config"
)

const (
	apiURL = "https://api.zoomeye.org"
)

type ZoomEye struct {
	client *http.Client
	token  string
	config *config.Config
}

func New(config *config.Config) *ZoomEye {
	return &ZoomEye{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (z *ZoomEye) Name() string {
	return "zoomeye"
}

func (z *ZoomEye) Init() error {
	if token, ok := z.config.Get("ZoomEye", "token"); ok {
		z.token = token
	}

	if z.token == "" {
		return fmt.Errorf("zoomeye token not configured")
	}

	return nil
}

func (z *ZoomEye) IsAvailable() bool {
	if z.token == "" {
		return false
	}

	req, err := http.NewRequest("GET", apiURL+"/resources-info", nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "JWT "+z.token)
	req.Header.Set("User-Agent", "curl/7.80.0")

	resp, err := z.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (z *ZoomEye) Search(dork string, pages int, resource string) ([]string, error) {
	if !z.IsAvailable() {
		return nil, fmt.Errorf("zoomeye token is not available")
	}

	var results []string

	for page := 1; page <= pages; page++ {
		time.Sleep(1 * time.Second)

		searchURL := fmt.Sprintf("%s/%s/search?query=%s&page=%d",
			apiURL, resource, url.QueryEscape(dork), page)

		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "JWT "+z.token)
		req.Header.Set("User-Agent", "curl/7.80.0")

		resp, err := z.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
		}

		var response struct {
			Matches []struct {
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				App      string `json:"appinfo"`
				Hostname string `json:"geoinfo"`
			} `json:"matches"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		for _, match := range response.Matches {
			ip := match.IP

			if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
				ip = fmt.Sprintf("[%s]", ip)
			}

			if resource == "host" {
				target := fmt.Sprintf("%s:%d", ip, match.Port)
				results = append(results, target)
			} else {
				protocol := strings.ToLower(match.Protocol)
				if protocol == "" {
					protocol = "http"
				}
				target := fmt.Sprintf("%s://%s:%d", protocol, ip, match.Port)
				results = append(results, target)
			}
		}
	}

	return results, nil
}

func (z *ZoomEye) SetToken(token string) error {
	z.token = token

	if err := z.config.Set("ZoomEye", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
