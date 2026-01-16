package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type HashType string

const (
	HashMD5    HashType = "md5"
	HashSHA1   HashType = "sha1"
	HashSHA256 HashType = "sha256"
)

func Hash(data string, hashType HashType) string {
	var h hash.Hash

	switch hashType {
	case HashMD5:
		h = md5.New()
	case HashSHA1:
		h = sha1.New()
	case HashSHA256:
		h = sha256.New()
	default:
		h = md5.New()
	}

	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func HashBytes(data []byte, hashType HashType) string {
	var h hash.Hash

	switch hashType {
	case HashMD5:
		h = md5.New()
	case HashSHA1:
		h = sha1.New()
	case HashSHA256:
		h = sha256.New()
	default:
		h = md5.New()
	}

	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func Base64URLEncode(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

func Base64URLDecode(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func HexEncode(data string) string {
	return hex.EncodeToString([]byte(data))
}

func HexDecode(data string) (string, error) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func XOREncode(data string, key byte) string {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key
	}
	return string(result)
}

func XORDecode(data string, key byte) string {
	return XOREncode(data, key)
}

func IsValidURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

func IsValidIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		if num < 0 || num > 255 {
			return false
		}
	}

	return true
}

func IsValidPort(s string) bool {
	port, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}

func IsValidEmail(s string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(s)
}

func GetDomain(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	return parsed.Hostname(), nil
}

func GetPath(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	return parsed.Path, nil
}

func GetQuery(u string) (url.Values, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	return parsed.Query(), nil
}

func BuildURL(scheme, host, path string, params url.Values) string {
	u := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: params.Encode(),
	}
	return u.String()
}

func JoinURL(base, path string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")
	path = strings.TrimPrefix(path, "/")

	baseURL.Path += "/" + path

	return baseURL.String(), nil
}

func Now() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func NowUnix() int64 {
	return time.Now().Unix()
}

func NowUnixNano() int64 {
	return time.Now().UnixNano()
}

func FormatTime(t time.Time, format string) string {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	return t.Format(format)
}

func ParseTime(s string, format string) (time.Time, error) {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	return time.Parse(format, s)
}

func TimestampToTime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0)
}

func TimeToTimestamp(t time.Time) int64 {
	return t.Unix()
}

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}

	return string(result)
}

func RandomNumber(min, max int) int {
	return min + int(time.Now().UnixNano()%int64(max-min+1))
}

func Contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func ContainsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if Contains(s, substr) {
			return true
		}
	}
	return false
}

func StartsWith(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

func EndsWith(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
}

func Trim(s string) string {
	return strings.TrimSpace(s)
}

func TrimPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}

func TrimSuffix(s, suffix string) string {
	return strings.TrimSuffix(s, suffix)
}

func Split(s, sep string) []string {
	return strings.Split(s, sep)
}

func Join(sep string, parts ...string) string {
	return strings.Join(parts, sep)
}

func Replace(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}

func ToLower(s string) string {
	return strings.ToLower(s)
}

func ToUpper(s string) string {
	return strings.ToUpper(s)
}

func ToTitle(s string) string {
	return strings.Title(s)
}

func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

func ToInt(s string) (int, error) {
	return strconv.Atoi(s)
}

func ToInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func ToFloat64(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

func ToBool(s string) (bool, error) {
	return strconv.ParseBool(s)
}

func FromInt(i int) string {
	return strconv.Itoa(i)
}

func FromInt64(i int64) string {
	return strconv.FormatInt(i, 10)
}

func FromFloat64(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func FromBool(b bool) string {
	return strconv.FormatBool(b)
}

func FormatBytes(bytes int64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

func Retry(fn func() error, maxAttempts int, delay time.Duration) error {
	var err error

	for i := 0; i < maxAttempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		if i < maxAttempts-1 {
			time.Sleep(delay)
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", maxAttempts, err)
}

func SafeExecute(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered: %v", r)
		}
	}()

	fn()
	return nil
}

func Chunk(slice []string, size int) [][]string {
	if size <= 0 {
		return [][]string{slice}
	}

	var chunks [][]string
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func Unique(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func Reverse(slice []string) []string {
	result := make([]string, len(slice))
	for i, item := range slice {
		result[len(slice)-1-i] = item
	}
	return result
}

func Filter(slice []string, predicate func(string) bool) []string {
	result := make([]string, 0)
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func Map(slice []string, fn func(string) string) []string {
	result := make([]string, len(slice))
	for i, item := range slice {
		result[i] = fn(item)
	}
	return result
}

func Reduce(slice []string, initial string, fn func(acc, item string) string) string {
	result := initial
	for _, item := range slice {
		result = fn(result, item)
	}
	return result
}
