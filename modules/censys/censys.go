package censys

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
	apiURL = "https://search.censys.io/api/v2"
)

type Censys struct {
	client    *http.Client
	apiID     string
	apiSecret string
	config    *config.Config
}

func New(config *config.Config) *Censys {
	return &Censys{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (c *Censys) Name() string {
	return "censys"
}

func (c *Censys) Init() error {
	if apiID, ok := c.config.Get("Censys", "api_id"); ok {
		c.apiID = apiID
	}
	if apiSecret, ok := c.config.Get("Censys", "api_secret"); ok {
		c.apiSecret = apiSecret
	}

	if c.apiID == "" || c.apiSecret == "" {
		return fmt.Errorf("censys credentials not configured")
	}

	return nil
}

func (c *Censys) IsAvailable() bool {
	if c.apiID == "" || c.apiSecret == "" {
		return false
	}

	req, err := http.NewRequest("GET", apiURL+"/account", nil)
	if err != nil {
		return false
	}

	req.SetBasicAuth(c.apiID, c.apiSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (c *Censys) Search(dork string, pages int, resource string) ([]string, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("censys credentials are not available")
	}

	var results []string

	for page := 1; page <= pages; page++ {
		time.Sleep(1 * time.Second)

		searchURL := fmt.Sprintf("%s/hosts/search?q=%s&per_page=100&page=%d",
			apiURL, url.QueryEscape(dork), page)

		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.SetBasicAuth(c.apiID, c.apiSecret)
		req.Header.Set("Accept", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
		}

		var response struct {
			Code   int `json:"code"`
			Result struct {
				Hits []struct {
					IP   string `json:"ip"`
					Host []struct {
						Name string `json:"name"`
					} `json:"services"`
					Services []struct {
						Port              int    `json:"port"`
						ServiceName       string `json:"service_name"`
						TransportProtocol string `json:"transport_protocol"`
					} `json:"services"`
				} `json:"hits"`
			} `json:"result"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		for _, hit := range response.Result.Hits {
			if resource == "host" {
				for _, svc := range hit.Services {
					target := fmt.Sprintf("%s:%d", hit.IP, svc.Port)
					results = append(results, target)
				}
			} else {
				for _, svc := range hit.Services {
					protocol := strings.ToLower(svc.ServiceName)
					if protocol == "" {
						protocol = strings.ToLower(svc.TransportProtocol)
					}
					if protocol == "" {
						protocol = "tcp"
					}
					target := fmt.Sprintf("%s://%s:%d", protocol, hit.IP, svc.Port)
					results = append(results, target)
				}
			}
		}
	}

	return results, nil
}

func (c *Censys) SetCredentials(apiID, apiSecret string) error {
	c.apiID = apiID
	c.apiSecret = apiSecret

	if err := c.config.Set("Censys", "api_id", apiID); err != nil {
		return fmt.Errorf("failed to save api_id: %w", err)
	}
	if err := c.config.Set("Censys", "api_secret", apiSecret); err != nil {
		return fmt.Errorf("failed to save api_secret: %w", err)
	}

	return nil
}
