package fofa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/seaung/pocsuite-go/config"
)

const (
	apiURL = "https://fofa.info/api/v1"
)

type Fofa struct {
	client *http.Client
	user   string
	token  string
	config *config.Config
}

func New(config *config.Config) *Fofa {
	return &Fofa{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (f *Fofa) Name() string {
	return "fofa"
}

func (f *Fofa) Init() error {
	if user, ok := f.config.Get("Fofa", "user"); ok {
		f.user = user
	}
	if token, ok := f.config.Get("Fofa", "token"); ok {
		f.token = token
	}

	if f.user == "" || f.token == "" {
		return fmt.Errorf("fofa credentials not configured")
	}

	return nil
}

func (f *Fofa) IsAvailable() bool {
	if f.user == "" || f.token == "" {
		return false
	}

	apiURL := fmt.Sprintf("%s/info/my?email=%s&key=%s", apiURL, f.user, f.token)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "curl/7.80.0")

	resp, err := f.client.Do(req)
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

	_, ok := result["username"]
	return ok
}

func (f *Fofa) Search(dork string, pages int, resource string) ([]string, error) {
	if !f.IsAvailable() {
		return nil, fmt.Errorf("fofa credentials are not available")
	}

	encodedDork := base64.StdEncoding.EncodeToString([]byte(dork))

	var fields string
	if resource == "host" {
		fields = "protocol,ip,port"
	} else {
		fields = "protocol,host"
	}

	var results []string

	for page := 1; page <= pages; page++ {
		time.Sleep(1 * time.Second)

		searchURL := fmt.Sprintf("%s/search/all?email=%s&key=%s&qbase64=%s&fields=%s&page=%d",
			apiURL, f.user, f.token, encodedDork, fields, page)

		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", "curl/7.80.0")

		resp, err := f.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("api request failed with status %d", resp.StatusCode)
		}

		var response struct {
			Error   bool            `json:"error"`
			Results [][]interface{} `json:"results"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		if response.Error {
			return nil, fmt.Errorf("fofa api returned an error")
		}

		for _, match := range response.Results {
			if resource == "host" {
				if len(match) >= 3 {
					protocol := fmt.Sprintf("%v", match[0])
					ip := fmt.Sprintf("%v", match[1])
					port := fmt.Sprintf("%v", match[2])

					if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
						ip = fmt.Sprintf("[%s]", ip)
					}

					target := fmt.Sprintf("%s://%s:%s", protocol, ip, port)
					results = append(results, target)
				}
			} else {
				if len(match) >= 2 {
					protocol := fmt.Sprintf("%v", match[0])
					host := fmt.Sprintf("%v", match[1])

					// Add protocol if not present
					if !strings.Contains(host, "://") {
						target := fmt.Sprintf("%s://%s", protocol, host)
						results = append(results, target)
					} else {
						results = append(results, host)
					}
				}
			}
		}
	}

	return results, nil
}

func (f *Fofa) SetCredentials(user, token string) error {
	f.user = user
	f.token = token

	if err := f.config.Set("Fofa", "user", user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}
	if err := f.config.Set("Fofa", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
