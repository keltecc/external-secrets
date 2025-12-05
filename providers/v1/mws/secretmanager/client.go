package secretmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	mwscommon "github.com/external-secrets/external-secrets/providers/v1/mws/common"
)

const (
	SecretManagerEndpoint = "https://secretmanager.mwsapis.ru/secretmanager/v1"
)

var (
	ErrNotImplemented       = errors.New("not implemented")
	ErrInvalidSecretVersion = errors.New("invalid secret version")
)

type SecretObj map[string]string

type Client struct {
	projectID     string
	tokenProvider *mwscommon.IAMTokenProvider
}

func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	secret, err := c.downloadSecret(ctx, ref.Key, ref.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to download secret: %w", err)
	}

	if ref.Property == "" {
		buffer, err := json.Marshal(secret)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal secret: %w", err)
		}

		return buffer, nil
	}

	property, ok := secret[ref.Property]
	if !ok {
		return nil, fmt.Errorf("secret does not contain property %s", ref.Property)
	}

	return []byte(property), nil
}

func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	secret, err := c.downloadSecret(ctx, ref.Key, ref.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to download secret: %w", err)
	}

	secretMap := make(map[string][]byte, len(secret))

	for key, value := range secret {
		secretMap[key] = []byte(value)
	}

	return secretMap, nil
}

func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, ErrNotImplemented
}

func (c *Client) PushSecret(context.Context, *corev1.Secret, esv1.PushSecretData) error {
	return ErrNotImplemented
}

func (c *Client) DeleteSecret(context.Context, esv1.PushSecretRemoteRef) error {
	return ErrNotImplemented
}

func (c *Client) SecretExists(context.Context, esv1.PushSecretRemoteRef) (bool, error) {
	return false, ErrNotImplemented
}

func (c *Client) Validate() (esv1.ValidationResult, error) {
	return esv1.ValidationResultUnknown, nil
}

func (c *Client) Close(_ context.Context) error {
	return nil
}

func (c *Client) downloadSecret(ctx context.Context, key string, version string) (SecretObj, error) {
	if version == "" {
		version = "current"
	}

	iamToken, err := c.tokenProvider.GetIAMToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get iam token: %w", err)
	}

	url := fmt.Sprintf(
		"%s/projects/%s/secrets/%s/secretVersions/%s:getData",
		SecretManagerEndpoint, c.projectID, key, version,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", iamToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do http request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrInvalidSecretVersion
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status code %d", resp.StatusCode)
	}

	obj := make(SecretObj)

	err = json.NewDecoder(resp.Body).Decode(&obj)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret body: %w", err)
	}

	return obj, nil
}
