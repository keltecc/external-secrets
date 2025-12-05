package certificatemanager

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
	CertificateManagerEndpoint = "https://certmanager.mwsapis.ru/certmanager/v1"

	propertyCertificate = "certificate"
	propertyPrivateKey  = "privateKey"
	propertyChainedCert = "chainedCert"
)

var (
	ErrNotImplemented         = errors.New("not implemented")
	ErrInvalidCertificateName = errors.New("invalid certificate name")
)

type CertificateObj struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	ChainedCert string `json:"chainedCert,omitempty"`
}

type Client struct {
	projectID     string
	tokenProvider *mwscommon.IAMTokenProvider
}

func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	certificate, err := c.downloadCertificate(ctx, ref.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %w", err)
	}

	if ref.Property == "" {
		buffer, err := json.Marshal(certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificate: %w", err)
		}

		return buffer, nil
	}

	switch ref.Property {
	case propertyCertificate:
		return []byte(certificate.Certificate), nil

	case propertyPrivateKey:
		return []byte(certificate.PrivateKey), nil

	case propertyChainedCert:
		return []byte(certificate.ChainedCert), nil
	}

	return nil, fmt.Errorf("invalid certificate property %s", ref.Property)
}

func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	certificate, err := c.downloadCertificate(ctx, ref.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %w", err)
	}

	secretMap := make(map[string][]byte, 3)

	secretMap[propertyCertificate] = []byte(certificate.Certificate)
	secretMap[propertyPrivateKey] = []byte(certificate.PrivateKey)

	if certificate.ChainedCert != "" {
		secretMap[propertyChainedCert] = []byte(certificate.ChainedCert)
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

func (c *Client) downloadCertificate(ctx context.Context, name string) (CertificateObj, error) {
	iamToken, err := c.tokenProvider.GetIAMToken(ctx)
	if err != nil {
		return CertificateObj{}, fmt.Errorf("failed to get iam token: %w", err)
	}

	url := fmt.Sprintf(
		"%s/projects/%s/certificates/%s:download",
		CertificateManagerEndpoint, c.projectID, name,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return CertificateObj{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", iamToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return CertificateObj{}, fmt.Errorf("failed to do http request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return CertificateObj{}, ErrInvalidCertificateName
	}

	if resp.StatusCode != http.StatusOK {
		return CertificateObj{}, fmt.Errorf("unexpected http status code %d", resp.StatusCode)
	}

	var obj CertificateObj

	err = json.NewDecoder(resp.Body).Decode(&obj)
	if err != nil {
		return CertificateObj{}, fmt.Errorf("failed to decode certificate body: %w", err)
	}

	return obj, nil
}
