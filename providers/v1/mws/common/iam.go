package common

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	IAMEndpoint         = "https://iam.mwsapis.ru/iam/v1"
	TokenRefreshTimeout = 1 * time.Hour
)

type issueTokenResponse struct {
	AccessToken         string `json:"accessToken"`
	ExpirationTimestamp string `json:"expirationTs"`
}

type CurrentTimeFunc func() time.Time

type IAMTokenProvider struct {
	mu sync.Mutex

	currentTime   CurrentTimeFunc
	authorizedKey *AuthorizedKey

	privateKey       *ecdsa.PrivateKey
	lastToken        string
	lastTokenCreated time.Time
}

func NewIAMTokenProvider(
	currentTime CurrentTimeFunc,
	authorizedKey *AuthorizedKey,
) (*IAMTokenProvider, error) {
	if err := authorizedKey.Validate(); err != nil {
		return nil, fmt.Errorf("authorized key validation failed: %w", err)
	}

	block, _ := base64.StdEncoding.DecodeString(authorizedKey.PrivateKey)
	privateKeyPEM, err := x509.ParsePKCS8PrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := privateKeyPEM.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}

	return &IAMTokenProvider{
		currentTime:   currentTime,
		authorizedKey: authorizedKey,
		privateKey:    privateKey,
	}, nil
}

func (p *IAMTokenProvider) GetIAMToken(ctx context.Context) (string, error) {
	expiration := p.currentTime().Add(-TokenRefreshTimeout)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lastToken == "" || p.lastTokenCreated.After(expiration) {
		err := p.refreshIAMToken(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to refresh iam token: %w", err)
		}
	}

	return p.lastToken, nil
}

func (p *IAMTokenProvider) refreshIAMToken(ctx context.Context) error {
	now := p.currentTime()

	keyParts := strings.Split(p.authorizedKey.KeyId, "/")
	serviceAccountId := strings.Join(keyParts[:4], "/")
	authorizedKeyId := keyParts[5]

	jwt, err := p.createJwtToken(serviceAccountId, authorizedKeyId)
	if err != nil {
		return fmt.Errorf("failed to create jwt token: %w", err)
	}

	url := fmt.Sprintf(
		"%s/tokens/:issueServiceAccountToken?serviceAccount=%s",
		IAMEndpoint, serviceAccountId,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", jwt)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do http request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status code %d", resp.StatusCode)
	}

	var obj issueTokenResponse

	err = json.NewDecoder(resp.Body).Decode(&obj)
	if err != nil {
		return fmt.Errorf("failed to decode response body: %w", err)
	}

	p.lastToken = obj.AccessToken
	p.lastTokenCreated = now

	return nil
}

func (p *IAMTokenProvider) createJwtToken(serviceAccountId string, authorizedKeyId string) (string, error) {
	expiration := p.currentTime().Add(2 * TokenRefreshTimeout)

	token := jwt.New(jwt.SigningMethodES256)

	token.Header = map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"kid": authorizedKeyId,
	}

	token.Claims = jwt.MapClaims(map[string]interface{}{
		"sub": serviceAccountId,
		"exp": expiration.UTC().Unix(),
	})

	result, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt token: %v", err)
	}

	return result, nil
}
