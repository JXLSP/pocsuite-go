package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
	headers    map[string]string
	cookies    map[string]string
	timeout    time.Duration
	proxy      string
	verifySSL  bool
}

type Response struct {
	*http.Response
	BodyText   string
	Headers    map[string]string
	Cookies    map[string]string
	StatusCode int
}

type Config struct {
	Timeout   time.Duration
	Proxy     string
	VerifySSL bool
	UserAgent string
}

func DefaultConfig() *Config {
	return &Config{
		Timeout:   30 * time.Second,
		VerifySSL: true,
		UserAgent: "pocsuite-go/1.0",
	}
}

func NewClient(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		headers:   make(map[string]string),
		cookies:   make(map[string]string),
		timeout:   config.Timeout,
		proxy:     config.Proxy,
		verifySSL: config.VerifySSL,
	}
}

func (c *Client) SetHeader(key, value string) {
	c.headers[key] = value
}

func (c *Client) SetHeaders(headers map[string]string) {
	for k, v := range headers {
		c.headers[k] = v
	}
}

func (c *Client) SetCookie(key, value string) {
	c.cookies[key] = value
}

func (c *Client) SetCookies(cookies map[string]string) {
	for k, v := range cookies {
		c.cookies[k] = v
	}
}

func (c *Client) Get(urlStr string) (*Response, error) {
	return c.Request("GET", urlStr, nil, nil)
}

func (c *Client) Post(urlStr string, data interface{}) (*Response, error) {
	return c.Request("POST", urlStr, data, nil)
}

func (c *Client) Put(urlStr string, data interface{}) (*Response, error) {
	return c.Request("PUT", urlStr, data, nil)
}

func (c *Client) Delete(urlStr string) (*Response, error) {
	return c.Request("DELETE", urlStr, nil, nil)
}

func (c *Client) Request(method, urlStr string, data interface{}, headers map[string]string) (*Response, error) {
	var body io.Reader

	if data != nil {
		switch v := data.(type) {
		case string:
			body = strings.NewReader(v)
		case []byte:
			body = bytes.NewReader(v)
		case map[string]string:
			values := url.Values{}
			for key, val := range v {
				values.Set(key, val)
			}
			body = strings.NewReader(values.Encode())
		}
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if len(c.cookies) > 0 {
		var cookieStrings []string
		for k, v := range c.cookies {
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", k, v))
		}
		req.Header.Set("Cookie", strings.Join(cookieStrings, "; "))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	respCookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		respCookies[cookie.Name] = cookie.Value
	}

	return &Response{
		Response:   resp,
		BodyText:   string(bodyBytes),
		Headers:    respHeaders,
		Cookies:    respCookies,
		StatusCode: resp.StatusCode,
	}, nil
}

func (c *Client) RequestWithContext(ctx context.Context, method, urlStr string, data interface{}, headers map[string]string) (*Response, error) {
	var body io.Reader

	if data != nil {
		switch v := data.(type) {
		case string:
			body = strings.NewReader(v)
		case []byte:
			body = bytes.NewReader(v)
		case map[string]string:
			values := url.Values{}
			for key, val := range v {
				values.Set(key, val)
			}
			body = strings.NewReader(values.Encode())
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if len(c.cookies) > 0 {
		var cookieStrings []string
		for k, v := range c.cookies {
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", k, v))
		}
		req.Header.Set("Cookie", strings.Join(cookieStrings, "; "))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	respCookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		respCookies[cookie.Name] = cookie.Value
	}

	return &Response{
		Response:   resp,
		BodyText:   string(bodyBytes),
		Headers:    respHeaders,
		Cookies:    respCookies,
		StatusCode: resp.StatusCode,
	}, nil
}

func (r *Response) GetStatusCode() int {
	return r.StatusCode
}

func (r *Response) GetBody() string {
	return r.BodyText
}

func (r *Response) GetHeader(key string) string {
	return r.Headers[key]
}

func (r *Response) GetCookie(key string) string {
	return r.Cookies[key]
}

func (r *Response) Contains(substr string) bool {
	return strings.Contains(r.BodyText, substr)
}

func (r *Response) ContainsAny(substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(r.BodyText, substr) {
			return true
		}
	}
	return false
}

func (r *Response) RegexMatch(pattern string) bool {
	return false
}
