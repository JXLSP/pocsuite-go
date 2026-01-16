package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/seaung/pocsuite-go/request"
)

type SessionManager struct {
	sessions map[string]*http.Client
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*http.Client),
	}
}

func (sm *SessionManager) GetSession(sessionID string) *http.Client {
	sm.mu.RLock()
	client, exists := sm.sessions[sessionID]
	sm.mu.RUnlock()

	if exists {
		return client
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if client, exists := sm.sessions[sessionID]; exists {
		return client
	}

	jar, _ := cookiejar.New(nil)
	client = &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 30 * time.Second,
	}

	sm.sessions[sessionID] = client
	return client
}

func (sm *SessionManager) RemoveSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) ClearAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions = make(map[string]*http.Client)
}

type RequestConfig struct {
	Method        string
	URL           string
	Headers       map[string]string
	Cookies       map[string]string
	Data          interface{}
	Proxy         string
	Timeout       time.Duration
	VerifySSL     bool
	AllowRedirect bool
	SessionID     string
}

func DefaultRequestConfig() *RequestConfig {
	return &RequestConfig{
		Method:        "GET",
		Headers:       make(map[string]string),
		Cookies:       make(map[string]string),
		Timeout:       30 * time.Second,
		VerifySSL:     true,
		AllowRedirect: true,
	}
}

type RequestBuilder struct {
	config *RequestConfig
}

func NewRequestBuilder() *RequestBuilder {
	return &RequestBuilder{
		config: DefaultRequestConfig(),
	}
}

func (rb *RequestBuilder) SetMethod(method string) *RequestBuilder {
	rb.config.Method = method
	return rb
}

func (rb *RequestBuilder) SetURL(url string) *RequestBuilder {
	rb.config.URL = url
	return rb
}

func (rb *RequestBuilder) SetHeader(key, value string) *RequestBuilder {
	rb.config.Headers[key] = value
	return rb
}

func (rb *RequestBuilder) SetHeaders(headers map[string]string) *RequestBuilder {
	for k, v := range headers {
		rb.config.Headers[k] = v
	}
	return rb
}

func (rb *RequestBuilder) SetCookie(key, value string) *RequestBuilder {
	rb.config.Cookies[key] = value
	return rb
}

func (rb *RequestBuilder) SetCookies(cookies map[string]string) *RequestBuilder {
	for k, v := range cookies {
		rb.config.Cookies[k] = v
	}
	return rb
}

func (rb *RequestBuilder) SetData(data interface{}) *RequestBuilder {
	rb.config.Data = data
	return rb
}

func (rb *RequestBuilder) SetProxy(proxy string) *RequestBuilder {
	rb.config.Proxy = proxy
	return rb
}

func (rb *RequestBuilder) SetTimeout(timeout time.Duration) *RequestBuilder {
	rb.config.Timeout = timeout
	return rb
}

func (rb *RequestBuilder) SetVerifySSL(verify bool) *RequestBuilder {
	rb.config.VerifySSL = verify
	return rb
}

func (rb *RequestBuilder) SetAllowRedirect(allow bool) *RequestBuilder {
	rb.config.AllowRedirect = allow
	return rb
}

func (rb *RequestBuilder) SetSessionID(sessionID string) *RequestBuilder {
	rb.config.SessionID = sessionID
	return rb
}

func (rb *RequestBuilder) Build() *RequestConfig {
	return rb.config
}

type RequestManager struct {
	sessionManager *SessionManager
	client         *http.Client
	defaultConfig  *RequestConfig
	hooks          []RequestHook
	mu             sync.RWMutex
}

type RequestHook interface {
	BeforeRequest(req *http.Request) error
	AfterResponse(resp *http.Response) error
}

func NewRequestManager() *RequestManager {
	return &RequestManager{
		sessionManager: NewSessionManager(),
		defaultConfig:  DefaultRequestConfig(),
		hooks:          make([]RequestHook, 0),
	}
}

func (rm *RequestManager) AddHook(hook RequestHook) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.hooks = append(rm.hooks, hook)
}

func (rm *RequestManager) RemoveHook(hook RequestHook) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, h := range rm.hooks {
		if h == hook {
			rm.hooks = append(rm.hooks[:i], rm.hooks[i+1:]...)
			break
		}
	}
}

func (rm *RequestManager) Execute(config *RequestConfig) (*request.Response, error) {
	if config == nil {
		config = rm.defaultConfig
	}

	var client *http.Client
	if config.SessionID != "" {
		client = rm.sessionManager.GetSession(config.SessionID)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if !config.AllowRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
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

		client = &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		}
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if !config.AllowRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	var body io.Reader
	if config.Data != nil {
		switch v := config.Data.(type) {
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

	req, err := http.NewRequest(config.Method, config.URL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	if len(config.Cookies) > 0 {
		var cookieStrings []string
		for k, v := range config.Cookies {
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", k, v))
		}
		req.Header.Set("Cookie", strings.Join(cookieStrings, "; "))
	}

	rm.mu.RLock()
	hooks := make([]RequestHook, len(rm.hooks))
	copy(hooks, rm.hooks)
	rm.mu.RUnlock()

	for _, hook := range hooks {
		if err := hook.BeforeRequest(req); err != nil {
			return nil, fmt.Errorf("before request hook failed: %w", err)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	for _, hook := range hooks {
		if err := hook.AfterResponse(resp); err != nil {
			return nil, fmt.Errorf("after response hook failed: %w", err)
		}
	}

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

	return &request.Response{
		Response:   resp,
		BodyText:   string(bodyBytes),
		Headers:    respHeaders,
		Cookies:    respCookies,
		StatusCode: resp.StatusCode,
	}, nil
}

func (rm *RequestManager) Get(url string) (*request.Response, error) {
	return rm.Execute(&RequestConfig{
		Method: "GET",
		URL:    url,
	})
}

func (rm *RequestManager) Post(url string, data interface{}) (*request.Response, error) {
	return rm.Execute(&RequestConfig{
		Method: "POST",
		URL:    url,
		Data:   data,
	})
}

func (rm *RequestManager) Put(url string, data interface{}) (*request.Response, error) {
	return rm.Execute(&RequestConfig{
		Method: "PUT",
		URL:    url,
		Data:   data,
	})
}

func (rm *RequestManager) Delete(url string) (*request.Response, error) {
	return rm.Execute(&RequestConfig{
		Method: "DELETE",
		URL:    url,
	})
}

func (rm *RequestManager) GetSession(sessionID string) *http.Client {
	return rm.sessionManager.GetSession(sessionID)
}

func (rm *RequestManager) RemoveSession(sessionID string) {
	rm.sessionManager.RemoveSession(sessionID)
}

func (rm *RequestManager) ClearSessions() {
	rm.sessionManager.ClearAll()
}

var DefaultRequestManager = NewRequestManager()

func Get(url string) (*request.Response, error) {
	return DefaultRequestManager.Get(url)
}

func Post(url string, data interface{}) (*request.Response, error) {
	return DefaultRequestManager.Post(url, data)
}

func Put(url string, data interface{}) (*request.Response, error) {
	return DefaultRequestManager.Put(url, data)
}

func Delete(url string) (*request.Response, error) {
	return DefaultRequestManager.Delete(url)
}

func Execute(config *RequestConfig) (*request.Response, error) {
	return DefaultRequestManager.Execute(config)
}

func RequestWithContext(ctx context.Context, config *RequestConfig) (*request.Response, error) {
	if config == nil {
		config = DefaultRequestConfig()
	}

	var body io.Reader
	if config.Data != nil {
		switch v := config.Data.(type) {
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

	req, err := http.NewRequestWithContext(ctx, config.Method, config.URL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	if len(config.Cookies) > 0 {
		var cookieStrings []string
		for k, v := range config.Cookies {
			cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", k, v))
		}
		req.Header.Set("Cookie", strings.Join(cookieStrings, "; "))
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

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !config.AllowRedirect {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err := client.Do(req)
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

	return &request.Response{
		Response:   resp,
		BodyText:   string(bodyBytes),
		Headers:    respHeaders,
		Cookies:    respCookies,
		StatusCode: resp.StatusCode,
	}, nil
}
