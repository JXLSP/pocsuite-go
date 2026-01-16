package interactsh

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/seaung/pocsuite-go/config"
)

type Interactsh struct {
	client        *http.Client
	server        string
	token         string
	publicKey     []byte
	privateKey    *rsa.PrivateKey
	secret        string
	correlationID string
	domain        string
	config        *config.Config
}

func New(config *config.Config) *Interactsh {
	return &Interactsh{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		config: config,
	}
}

func (i *Interactsh) Name() string {
	return "interactsh"
}

func (i *Interactsh) Init() error {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	i.privateKey = privateKey

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	i.publicKey = publicKeyBytes

	if server, ok := i.config.Get("Interactsh", "server"); ok {
		i.server = server
	} else {
		i.server = "oast.me"
	}

	if token, ok := i.config.Get("Interactsh", "token"); ok {
		i.token = token
	}

	i.secret = generateUUID()
	guid := generateGUID()
	i.domain = fmt.Sprintf("%s.%s", guid, i.server)
	i.correlationID = i.domain[:20]

	if err := i.register(); err != nil {
		return fmt.Errorf("failed to register with interactsh server: %w", err)
	}

	return nil
}

func (i *Interactsh) IsAvailable() bool {
	if i.server == "" || i.correlationID == "" {
		return false
	}
	return true
}

func (i *Interactsh) GetDomain() string {
	return i.domain
}

func (i *Interactsh) GetURL() string {
	return fmt.Sprintf("http://%s", i.domain)
}

func (i *Interactsh) CheckInteraction() bool {
	results := i.poll()
	return len(results) > 0
}

func (i *Interactsh) register() error {
	data := map[string]string{
		"public-key":     base64.StdEncoding.EncodeToString(i.publicKey),
		"secret-key":     i.secret,
		"correlation-id": i.correlationID,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/register", i.server), strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if i.token != "" {
		req.Header.Set("Authorization", i.token)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication error")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	return nil
}

func (i *Interactsh) poll() []map[string]interface{} {
	var results []map[string]interface{}

	for count := 0; count < 3; count++ {
		url := fmt.Sprintf("http://%s/poll?id=%s&secret=%s", i.server, i.correlationID, i.secret)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		if i.token != "" {
			req.Header.Set("Authorization", i.token)
		}

		resp, err := i.client.Do(req)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(1 * time.Second)
			continue
		}

		var response struct {
			AESKey string   `json:"aes_key"`
			Data   []string `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			resp.Body.Close()
			time.Sleep(1 * time.Second)
			continue
		}
		resp.Body.Close()

		for _, data := range response.Data {
			decrypted, err := i.decryptData(response.AESKey, data)
			if err == nil {
				results = append(results, decrypted)
			}
		}

		return results
	}

	return results
}

func (i *Interactsh) decryptData(aesKeyB64, dataB64 string) (map[string]interface{}, error) {
	aesKeyBytes, err := base64.StdEncoding.DecodeString(aesKeyB64)
	if err != nil {
		return nil, err
	}

	aesPlainKey, err := rsa.DecryptOAEP(sha256.New(), cryptorand.Reader, i.privateKey, aesKeyBytes, nil)
	if err != nil {
		return nil, err
	}

	dataBytes, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesPlainKey)
	if err != nil {
		return nil, err
	}

	if len(dataBytes) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := dataBytes[:aes.BlockSize]
	ciphertext := dataBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	if len(plaintext) < 16 {
		return nil, fmt.Errorf("plaintext too short")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(plaintext[16:], &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (i *Interactsh) BuildRequest(length int, method string) (string, string) {
	flag := randomString(length)
	url := fmt.Sprintf("%s.%s", flag, i.domain)

	if strings.HasPrefix(method, "http") {
		url = fmt.Sprintf("%s://%s", method, url)
	}

	return url, flag
}

func (i *Interactsh) Verify(flag string, getResult bool) (bool, []map[string]interface{}) {
	results := i.poll()
	for _, item := range results {
		if fullID, ok := item["full-id"].(string); ok {
			if strings.Contains(strings.ToLower(fullID), strings.ToLower(flag)) {
				return true, results
			}
		}
	}
	return false, results
}

func (i *Interactsh) SetCredentials(server, token string) error {
	i.server = server
	i.token = token

	if err := i.config.Set("Interactsh", "server", server); err != nil {
		return fmt.Errorf("failed to save server: %w", err)
	}
	if err := i.config.Set("Interactsh", "token", token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

func generateUUID() string {
	b := make([]byte, 16)
	cryptorand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generateGUID() string {
	uuid := generateUUID()
	guid := strings.ReplaceAll(uuid, "-", "")
	guid = guid + strings.Repeat("a", 33-len(guid))

	result := make([]byte, 33)
	for i, c := range guid {
		if c >= '0' && c <= '9' {
			result[i] = byte(c)
		} else {
			shift := mathrand.Intn(20)
			newChar := byte((int(c) + shift))
			if newChar > 'z' {
				newChar = 'a' + (newChar - 'z' - 1)
			}
			result[i] = newChar
		}
	}

	return string(result)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}
