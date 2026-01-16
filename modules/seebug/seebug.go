package seebug

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
	apiURL = "https://www.seebug.org/api"
)

type Seebug struct {
	client *http.Client
	token  string
	pocs   []map[string]interface{}
	config *config.Config
}

func New(config *config.Config) *Seebug {
	return &Seebug{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		config: config,
	}
}

func (s *Seebug) Name() string {
	return "seebug"
}

func (s *Seebug) Init() error {
	if token, ok := s.config.Get("Seebug", "token"); ok {
		s.token = token
	}

	if s.token == "" {
		return fmt.Errorf("seebug token not configured")
	}

	if !s.tokenIsAvailable() {
		return fmt.Errorf("seebug token is invalid")
	}

	return nil
}

func (s *Seebug) IsAvailable() bool {
	if s.token == "" {
		return false
	}
	return s.tokenIsAvailable()
}

func (s *Seebug) tokenIsAvailable() bool {
	if s.token == "" {
		return false
	}

	apiURL := fmt.Sprintf("%s/user/poc_list", apiURL)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "curl/7.80.0")
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.token))

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	if err := json.NewDecoder(resp.Body).Decode(&s.pocs); err != nil {
		return false
	}

	return true
}

func (s *Seebug) GetAvailablePocs() []map[string]interface{} {
	return s.pocs
}

func (s *Seebug) SearchPoc(keyword string) ([]map[string]interface{}, error) {
	apiURL := fmt.Sprintf("%s/user/poc_list?q=%s", apiURL, url.QueryEscape(keyword))
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "curl/7.80.0")
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.token))

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
	}

	var pocs []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&pocs); err != nil {
		return nil, err
	}

	return pocs, nil
}

func (s *Seebug) FetchPOC(ssvid string) (string, error) {
	if strings.HasPrefix(ssvid, "ssvid-") {
		ssvid = strings.TrimPrefix(ssvid, "ssvid-")
	}

	apiURL := fmt.Sprintf("%s/user/poc_detail?id=%s", apiURL, url.QueryEscape(ssvid))
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "curl/7.80.0")
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", s.token))

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api request failed with status %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if status, ok := response["status"].(bool); ok && !status {
		if message, ok := response["message"].(string); ok {
			if message == "没有权限访问此漏洞" {
				return "", fmt.Errorf("[PLUGIN] Seebug: No permission to access the vulnerability PoC")
			}
			return "", fmt.Errorf("[PLUGIN] Seebug: %s", message)
		}
		return "", fmt.Errorf("[PLUGIN] Seebug: Unknown error")
	}

	if code, ok := response["code"].(string); ok {
		return code, nil
	}

	return "", fmt.Errorf("no POC code found in response")
}

func (s *Seebug) SetToken(token string) error {
	s.token = token

	if err := s.config.Set("Seebug", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	if !s.tokenIsAvailable() {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func (s *Seebug) SearchVuln(cveID string) (map[string]interface{}, error) {
	pocs, err := s.SearchPoc(cveID)
	if err != nil {
		return nil, err
	}

	if len(pocs) == 0 {
		return nil, fmt.Errorf("no vulnerabilities found for %s", cveID)
	}

	result := make(map[string]interface{})
	result["cve_id"] = cveID
	result["pocs"] = pocs
	result["count"] = len(pocs)

	return result, nil
}
