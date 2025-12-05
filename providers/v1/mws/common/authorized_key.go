package common

import (
	"encoding/json"
	"fmt"
	"strings"
)

type AuthorizedKey struct {
	KeyId      string `json:"keyId"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Algorithm  string `json:"algorithm"`
}

func (k *AuthorizedKey) Validate() error {
	if k.Algorithm != "ES256" {
		return fmt.Errorf("unsupported algorithm: %s", k.Algorithm)
	}

	if len(strings.Split(k.KeyId, "/")) != 6 {
		return fmt.Errorf("invalid key id: %s", k.KeyId)
	}

	return nil
}

func ParseAuthorizedKey(obj string) (*AuthorizedKey, error) {
	authorizedKey := &AuthorizedKey{}

	err := json.Unmarshal([]byte(obj), authorizedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	return authorizedKey, nil
}
