package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

type MWSAuth struct {
	AuthorizedKey esmeta.SecretKeySelector `json:"authorizedKeySecretRef"`
}

type MWSSecretManagerProvider struct {
	Auth MWSAuth `json:"auth"`

	ProjectID string `json:"projectID,omitempty"`
}

type MWSCertificateManagerProvider struct {
	Auth MWSAuth `json:"auth"`

	ProjectID string `json:"projectID,omitempty"`
}
