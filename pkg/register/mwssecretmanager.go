//go:build mwssecretmanager || all_providers

package register

import (
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	mwssecretmanager "github.com/external-secrets/external-secrets/providers/v1/mws/secretmanager"
)

func init() {
	esv1.Register(mwssecretmanager.NewProvider(), mwssecretmanager.ProviderSpec(), mwssecretmanager.MaintenanceStatus())
}
