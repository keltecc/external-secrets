package secretmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	mwscommon "github.com/external-secrets/external-secrets/providers/v1/mws/common"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		MWSSecretManager: &esv1.MWSSecretManagerProvider{},
	}
}

func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}

var _ esv1.Provider = &Provider{}
var _ esv1.SecretsClient = &Client{}

type Provider struct{}

func NewProvider() *Provider {
	return &Provider{}
}

func (p *Provider) NewClient(
	ctx context.Context,
	store esv1.GenericStore,
	kube kclient.Client,
	namespace string,
) (esv1.SecretsClient, error) {
	if _, err := p.ValidateStore(store); err != nil {
		return nil, fmt.Errorf("invalid store: %w", err)
	}

	authorizedKey, err := loadAuthorizedKey(ctx, store, kube, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorized key: %w", err)
	}

	spec := store.GetSpec()
	projectID := spec.Provider.MWSSecretManager.ProjectID

	tokenProvider, err := mwscommon.NewIAMTokenProvider(time.Now, authorizedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create iam token provider: %w", err)
	}

	return &Client{
		projectID:     projectID,
		tokenProvider: tokenProvider,
	}, nil
}

func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	if store == nil {
		return nil, errors.New("store is not provided")
	}

	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.MWSSecretManager == nil {
		return nil, errors.New("secret manager spec is not provided")
	}

	secretManagerProvider := spec.Provider.MWSSecretManager

	if secretManagerProvider.Auth.AuthorizedKey.Name == "" {
		return nil, errors.New("invalid spec: auth.authorizedKey is required")
	}

	if secretManagerProvider.ProjectID == "" {
		return nil, errors.New("invalid spec: projectID is required")
	}

	err := esutils.ValidateReferentSecretSelector(store, secretManagerProvider.Auth.AuthorizedKey)
	if err != nil {
		return nil, fmt.Errorf("invalid spec: auth.authorizedKey: %w", err)
	}

	return nil, nil
}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

func loadAuthorizedKey(
	ctx context.Context,
	store esv1.GenericStore,
	kube kclient.Client,
	namespace string,
) (*mwscommon.AuthorizedKey, error) {
	spec := store.GetSpec()

	obj, err := resolvers.SecretKeyRef(
		ctx,
		kube,
		store.GetKind(),
		namespace,
		&spec.Provider.MWSSecretManager.Auth.AuthorizedKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve secret key reference: %w", err)
	}

	authorizedKey, err := mwscommon.ParseAuthorizedKey(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorized key: %w", err)
	}

	return authorizedKey, nil
}
