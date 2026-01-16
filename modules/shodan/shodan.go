package shodan

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
	apiURL = "https://api.shodan.io"
)

type Shodan struct {
	client *http.Client
	token  string
	config *config.Config
}

func New(config *config.Config) *Shodan {
	return &Shodan{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (s *Shodan) Name() string {
	return "shodan"
}

func (s *Shodan) Init() error {
	if token, ok := s.config.Get("Shodan", "token"); ok {
		s.token = token
	}

	if s.token == "" {
		return fmt.Errorf("shodan token not configured")
	}

	return nil
}

func (s *Shodan) IsAvailable() bool {
	if s.token == "" {
		return false
	}

	apiURL := fmt.Sprintf("%s/account/profile?key=%s", apiURL, s.token)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "curl/7.80.0")

	resp, err := s.client.Do(req)
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

	_, ok := result["member"]
	return ok
}

func (s *Shodan) Search(dork string, pages int, resource string) ([]string, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("shodan token is not available")
	}

	encodedDork := url.QueryEscape(dork)

	var results []string

	for page := 1; page <= pages; page++ {
		time.Sleep(1 * time.Second)

		searchURL := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s&page=%d",
			apiURL, s.token, encodedDork, page)

		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", "curl/7.80.0")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
		}

		var response struct {
			Total   int `json:"total"`
			Matches []struct {
				IPStr     string   `json:"ip_str"`
				Port      int      `json:"port"`
				Hostnames []string `json:"hostnames"`
			} `json:"matches"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		for _, match := range response.Matches {
			ip := match.IPStr

			if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
				ip = fmt.Sprintf("[%s]", ip)
			}

			if resource == "host" {
				target := fmt.Sprintf("%s:%d", ip, match.Port)
				results = append(results, target)
			} else {
				if len(match.Hostnames) > 0 {
					target := fmt.Sprintf("http://%s:%d", match.Hostnames[0], match.Port)
					results = append(results, target)
				} else {
					target := fmt.Sprintf("http://%s:%d", ip, match.Port)
					results = append(results, target)
				}
			}
		}
	}

	return results, nil
}

func (s *Shodan) SetToken(token string) error {
	s.token = token

	// Save to config
	if err := s.config.Set("Shodan", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
