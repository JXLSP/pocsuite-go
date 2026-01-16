package spider

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/seaung/pocsuite-go/config"
	"golang.org/x/net/html"
)

type SpiderModule interface {
	Name() string
	Crawl(targetURL string, maxPages int, urlExt []string) (*CrawlResult, error)
	GetRedirectURL(targetURL string) (string, error)
}

type CrawlResult struct {
	URLs []string
	JS   []string
	Img  []string
}

type Spider struct {
	client *http.Client
	config *config.Config
}

func New(config *config.Config) *Spider {
	return &Spider{
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		config: config,
	}
}

func (s *Spider) Name() string {
	return "spider"
}

func (s *Spider) Init() error {
	if _, ok := s.config.Get("Spider", "timeout"); ok {
	}
	return nil
}

func (s *Spider) IsAvailable() bool {
	return s.client != nil
}

func (s *Spider) Crawl(url string, depth int) ([]string, error) {
	result, err := s.CrawlWithExtensions(url, depth, []string{})
	if err != nil {
		return nil, err
	}
	return result.URLs, nil
}

func (s *Spider) CrawlWithExtensions(targetURL string, maxPages int, urlExt []string) (*CrawlResult, error) {
	trueURL, err := s.GetRedirectURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get redirect URL: %w", err)
	}

	result := &CrawlResult{
		URLs: make([]string, 0),
		JS:   make([]string, 0),
		Img:  make([]string, 0),
	}

	pagesNeedVisit := []string{trueURL}
	visited := make(map[string]bool)
	pageCount := 0

	for pageCount < maxPages && len(pagesNeedVisit) > 0 {
		currentURL := pagesNeedVisit[0]
		pagesNeedVisit = pagesNeedVisit[1:]

		if visited[currentURL] {
			continue
		}
		visited[currentURL] = true

		links, err := s.parseLinks(currentURL, urlExt)
		if err != nil {
			continue
		}

		result.URLs = append(result.URLs, links.URLs...)
		result.JS = append(result.JS, links.JS...)
		result.Img = append(result.Img, links.Img...)

		pageCount += len(links.URLs)
		pagesNeedVisit = append(pagesNeedVisit, links.URLs...)
	}

	return result, nil
}

func (s *Spider) GetRedirectURL(targetURL string) (string, error) {
	resp, err := s.client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	trueURL := resp.Request.URL.String()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return trueURL, nil
	}

	bodyStr := string(body)

	metaRegex := regexp.MustCompile(`(?i)<meta[^<>]*?url\s*=([\d\w://\\.?=&;%-]*)[^<>]*`)
	if match := metaRegex.FindStringSubmatch(bodyStr); len(match) > 1 {
		redirectURL := match[1]
		if parsedURL, err := url.Parse(redirectURL); err == nil && parsedURL.IsAbs() {
			return redirectURL, nil
		}
		if joinedURL, err := url.JoinPath(targetURL, redirectURL); err == nil {
			return joinedURL, nil
		}
	}

	bodyRegex := regexp.MustCompile(`(?i)<body[^<>]*?location[\s\.\w]*=['"]?([\d\w://\\.?=&;%-]*)['"]?[^<>]*`)
	if match := bodyRegex.FindStringSubmatch(bodyStr); len(match) > 1 {
		redirectURL := match[1]
		if parsedURL, err := url.Parse(redirectURL); err == nil && parsedURL.IsAbs() {
			return redirectURL, nil
		}
		if joinedURL, err := url.JoinPath(targetURL, redirectURL); err == nil {
			return joinedURL, nil
		}
	}

	jsRegex := regexp.MustCompile(`(?i)<script.*?>[^<>]*?location\.(?:replace|href|assign)[=\("']*([\d\w://\\.?=&;%-]*)[^<>]*?</script>`)
	if match := jsRegex.FindStringSubmatch(bodyStr); len(match) > 1 {
		redirectURL := match[1]
		if parsedURL, err := url.Parse(redirectURL); err == nil && parsedURL.IsAbs() {
			return redirectURL, nil
		}
		if joinedURL, err := url.JoinPath(targetURL, redirectURL); err == nil {
			return joinedURL, nil
		}
	}

	return trueURL, nil
}

func (s *Spider) parseLinks(pageURL string, urlExt []string) (*CrawlResult, error) {
	result := &CrawlResult{
		URLs: make([]string, 0),
		JS:   make([]string, 0),
		Img:  make([]string, 0),
	}

	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return result, err
	}

	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	resp, err := s.client.Get(pageURL)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return result, nil
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return result, err
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						newURL := s.resolveURL(pageURL, attr.Val)
						newURL = strings.Split(newURL, "#")[0]
						newURL = strings.TrimSpace(newURL)

						if s.isOrigin(newURL, origin) {
							if len(urlExt) > 0 {
								urlWithoutQuery := strings.Split(newURL, "?")[0]
								urlWithoutQuery = strings.TrimSpace(urlWithoutQuery)
								if s.endsWithAny(urlWithoutQuery, urlExt) {
									result.URLs = append(result.URLs, newURL)
								}
							} else {
								result.URLs = append(result.URLs, newURL)
							}
						}
					}
				}
			case "img":
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						newURL := s.resolveURL(pageURL, attr.Val)
						newURL = strings.Split(newURL, "?")[0]
						newURL = strings.TrimSpace(newURL)

						if s.isOrigin(newURL, origin) && s.isImageExt(newURL) {
							result.Img = append(result.Img, newURL)
						}
					}
				}
			case "script":
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						newURL := s.resolveURL(pageURL, attr.Val)
						newURL = strings.Split(newURL, "?")[0]
						newURL = strings.TrimSpace(newURL)

						if s.isOrigin(newURL, origin) && strings.HasSuffix(strings.ToLower(newURL), ".js") {
							result.JS = append(result.JS, newURL)
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return result, nil
}

func (s *Spider) resolveURL(baseURL, relativeURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}

	rel, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}

	return base.ResolveReference(rel).String()
}

func (s *Spider) isOrigin(urlStr, origin string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	urlOrigin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	return urlOrigin == origin
}

func (s *Spider) isImageExt(urlStr string) bool {
	imgExts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico"}
	lowerURL := strings.ToLower(urlStr)
	for _, ext := range imgExts {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
	}
	return false
}

func (s *Spider) endsWithAny(str string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(str, suffix) {
			return true
		}
	}
	return false
}

func (s *Spider) ExtractLinks(htmlContent string) []string {
	links := make([]string, 0)

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return links
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					links = append(links, attr.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return links
}

func (s *Spider) ExtractJS(htmlContent string) []string {
	jsLinks := make([]string, 0)

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return jsLinks
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					jsLinks = append(jsLinks, attr.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return jsLinks
}

func (s *Spider) ExtractImages(htmlContent string) []string {
	imgLinks := make([]string, 0)

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return imgLinks
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "img" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					imgLinks = append(imgLinks, attr.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return imgLinks
}

func (s *Spider) GetPageContent(targetURL string) (string, error) {
	resp, err := s.client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return "", err
	}

	return buf.String(), nil
}
