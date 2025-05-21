package spider

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

var imgExt []string = []string{".jpg", ".jpeg", ".png", ".gif"}

type CrawlerSpider struct {
	baseURL *url.URL
	origin  [2]string
	urlExt  []string
	urls    map[string]map[string]bool
}

func (c *CrawlerSpider) Parse(selector *goquery.Selection) {
	selector.Each(func(i int, s *goquery.Selection) {
		attr, ok := s.Attr("href")
		if ok {
			c.parseLink("url", attr)
		} else {
			attr, ok = s.Attr("src")
			if ok {
				c.parseLink(filepath.Ext(attr), attr)
			}
		}
	})
}

func (c *CrawlerSpider) parseLink(key, val string) {
	newURL := c.baseURL.ResolveReference(&url.URL{Path: val})
	cleanURL := strings.SplitN(newURL.String(), "?", 2)[0]

	if key == "url" && c.isOrigin(cleanURL) {
	}
}

func (c *CrawlerSpider) isOrigin(target string) bool {
	baseURL, _ := url.Parse(target)
	return c.origin == [2]string{baseURL.Scheme, baseURL.Host}
}

func getURLs(url string) {}

func getRedirectURL(url string) string {
	return ""
}

func joinURL(base, path string) string {
	baseURL, _ := url.Parse(base)
	pathURL, _ := url.Parse(path)
	return baseURL.ResolveReference(pathURL).String()
}

func RunCrawler(url string, maxPages int, urlExt []string) []string {
	return []string{}
}
