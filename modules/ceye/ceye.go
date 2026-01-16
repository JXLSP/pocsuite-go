package ceye

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/seaung/pocsuite-go/config"
)

const (
	apiURL = "http://api.ceye.io/v1"
)

type CEye struct {
	client   *http.Client
	token    string
	identify string
	config   *config.Config
}

func New(config *config.Config) *CEye {
	return &CEye{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (c *CEye) Name() string {
	return "ceye"
}

func (c *CEye) Init() error {
	if token, ok := c.config.Get("CEye", "token"); ok {
		c.token = token
	}

	if c.token == "" {
		return fmt.Errorf("ceye token not configured")
	}

	if err := c.checkToken(); err != nil {
		return fmt.Errorf("failed to get identify: %w", err)
	}

	return nil
}

func (c *CEye) IsAvailable() bool {
	if c.token == "" {
		return false
	}

	if err := c.checkToken(); err != nil {
		return false
	}

	return c.identify != ""
}

func (c *CEye) GetDomain() string {
	return fmt.Sprintf("%s.ceye.io", c.identify)
}

func (c *CEye) GetURL() string {
	return fmt.Sprintf("http://%s", c.GetDomain())
}

func (c *CEye) CheckInteraction() bool {
	return c.identify != ""
}

func (c *CEye) checkToken() error {
	apiURL := fmt.Sprintf("%s/identify", apiURL)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "curl/7.80.0")
	req.Header.Set("Authorization", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("api request failed with status %d", resp.StatusCode)
	}

	var response struct {
		Data struct {
			Identify string `json:"identify"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	c.identify = response.Data.Identify
	return nil
}

func (c *CEye) VerifyRequest(flag string, recordType string) bool {
	for count := 0; count < 3; count++ {
		time.Sleep(1 * time.Second)

		apiURL := fmt.Sprintf("%s/records?token=%s&type=%s&filter=%s",
			apiURL, c.token, recordType, url.QueryEscape(flag))

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue
		}

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			continue
		}

		if strings.Contains(string(body), flag) {
			return true
		}
	}

	return false
}

func (c *CEye) ExactRequest(flag string, recordType string) string {
	for count := 0; count < 3; count++ {
		time.Sleep(1 * time.Second)

		apiURL := fmt.Sprintf("%s/records?token=%s&type=%s&filter=%s",
			apiURL, c.token, recordType, url.QueryEscape(flag))

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue
		}

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var response struct {
			Data []struct {
				Name string `json:"name"`
			} `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, item := range response.Data {
			name := item.Name
			if strings.Contains(name, flag) {
				result := getMiddleText(name, flag, flag, 0)
				if result != "" {
					return result
				}
			}
		}

		break
	}

	return ""
}

func (c *CEye) BuildRequest(value string, recordType string) map[string]string {
	ranstr := randomString(4)
	domain := c.GetSubdomain()
	urlStr := ""

	if recordType == "request" || recordType == "http" {
		urlStr = fmt.Sprintf("http://%s.%s/%s%s%s", ranstr, domain, ranstr, value, ranstr)
	} else if recordType == "dns" {
		re := regexp.MustCompile(`\W`)
		cleanValue := re.ReplaceAllString(value, "")
		urlStr = fmt.Sprintf("%s%s%s.%s", ranstr, cleanValue, ranstr, domain)
	}

	return map[string]string{
		"url":  urlStr,
		"flag": ranstr,
	}
}

func (c *CEye) GetSubdomain() string {
	return fmt.Sprintf("%s.ceye.io", c.identify)
}

func (c *CEye) SetToken(token string) error {
	c.token = token

	if err := c.config.Set("CEye", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return c.checkToken()
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func getMiddleText(text, prefix, suffix string, index int) string {
	startIndex := strings.Index(text, prefix)
	if startIndex == -1 {
		return ""
	}

	startIndex += len(prefix)

	endIndex := strings.Index(text[startIndex:], suffix)
	if endIndex == -1 {
		return ""
	}

	return text[startIndex : startIndex+endIndex]
}
