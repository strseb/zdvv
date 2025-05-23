package controlserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL      string
	sharedSecret string
	publicKeyPEM string
	publicKeyMu  sync.RWMutex
	revocation   *RevocationService
	client       *http.Client
	hostname     string
}

func NewClient(baseURL, sharedSecret, hostname string) *Client {
	if !strings.HasPrefix(baseURL, "https://") {
		panic("control server baseURL must use https://")
	}
	return &Client{
		baseURL:      baseURL,
		sharedSecret: sharedSecret,
		revocation:   NewRevocationService(),
		client:       &http.Client{Timeout: 10 * time.Second},
		hostname:     hostname,
	}
}

func (c *Client) authReq(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.sharedSecret)
}

// FetchPublicKey fetches the public key from the control server and stores it
func (c *Client) FetchPublicKey() error {
	req, err := http.NewRequest("GET", c.baseURL+"/info", nil)
	if err != nil {
		return err
	}
	c.authReq(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("control server /info failed: %s", resp.Status)
	}
	var info struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return err
	}
	if info.PublicKey == "" {
		return errors.New("no public key in /info response")
	}
	c.publicKeyMu.Lock()
	c.publicKeyPEM = info.PublicKey
	c.publicKeyMu.Unlock()
	return nil
}

// RegisterServer registers this server with the control server
func (c *Client) RegisterServer() error {
	body := map[string]string{"hostname": c.hostname}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", c.baseURL+"/servers", bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.authReq(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("control server /servers POST failed: %s", resp.Status)
	}
	return nil
}

// DeregisterServer removes this server from the control server
func (c *Client) DeregisterServer() error {
	body := map[string]string{"hostname": c.hostname}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("DELETE", c.baseURL+"/servers", bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.authReq(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("control server /servers DELETE failed: %s", resp.Status)
	}
	return nil
}

// FetchRevoked fetches the revoked JWT IDs from the control server and updates the local revocation list
func (c *Client) FetchRevoked() error {
	req, err := http.NewRequest("GET", c.baseURL+"/revoked", nil)
	if err != nil {
		return err
	}
	c.authReq(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("control server /revoked failed: %s", resp.Status)
	}
	var revoked struct {
		Revoked []string `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&revoked); err != nil {
		return err
	}
	for _, jti := range revoked.Revoked {
		c.revocation.Revoke(jti)
	}
	return nil
}

// GetPublicKeyPEM returns the current public key PEM
func (c *Client) GetPublicKeyPEM() string {
	c.publicKeyMu.RLock()
	defer c.publicKeyMu.RUnlock()
	return c.publicKeyPEM
}

// GetRevocationService returns the revocation service
func (c *Client) GetRevocationService() *RevocationService {
	return c.revocation
}
