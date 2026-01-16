package hunter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/seaung/pocsuite-go/config"
)

const (
	apiURL = "https://hunter.qianxin.com/openApi/search"
)

type Hunter struct {
	client *http.Client
	token  string
	config *config.Config
}

func New(config *config.Config) *Hunter {
	return &Hunter{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (h *Hunter) Name() string {
	return "hunter"
}

func (h *Hunter) Init() error {
	if token, ok := h.config.Get("Hunter", "token"); ok {
		h.token = token
	}

	if h.token == "" {
		return fmt.Errorf("hunter token not configured")
	}

	return nil
}

func (h *Hunter) IsAvailable() bool {
	if h.token == "" {
		return false
	}

	testQuery := base64.URLEncoding.EncodeToString([]byte(`ip="255.255.255.255"`))
	apiURL := fmt.Sprintf("%s?api-key=%s&search=%s&page=1&page_size=1",
		apiURL, h.token, testQuery)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "curl/7.80.0")

	resp, err := h.client.Do(req)
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

	if data, ok := result["data"].(map[string]interface{}); ok {
		_, ok = data["rest_quota"]
		return ok
	}

	return false
}

func (h *Hunter) Search(dork string, pages int, resource string) ([]string, error) {
	if !h.IsAvailable() {
		return nil, fmt.Errorf("hunter token is not available")
	}

	encodedDork := base64.URLEncoding.EncodeToString([]byte(dork))

	var results []string

	for page := 1; page <= pages; page++ {
		time.Sleep(1 * time.Second)

		searchURL := fmt.Sprintf("%s?api-key=%s&search=%s&page=%d&page_size=20&is_web=3",
			apiURL, h.token, encodedDork, page)

		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", "curl/7.80.0")

		resp, err := h.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
		}

		var response struct {
			Code int `json:"code"`
			Data struct {
				Arr []struct {
					URL string `json:"url"`
				} `json:"arr"`
			} `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		if response.Code != 200 {
			return nil, fmt.Errorf("api returned error code: %d", response.Code)
		}

		for _, item := range response.Data.Arr {
			results = append(results, item.URL)
		}
	}

	return results, nil
}

func (h *Hunter) SetToken(token string) error {
	h.token = token

	if err := h.config.Set("Hunter", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
