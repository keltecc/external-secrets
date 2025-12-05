//go:build mwscertificatemanager || all_providers

package register

import (
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	mwscertificatemanager "github.com/external-secrets/external-secrets/providers/v1/mws/certificatemanager"
)

func init() {
	esv1.Register(mwscertificatemanager.NewProvider(), mwscertificatemanager.ProviderSpec(), mwscertificatemanager.MaintenanceStatus())
}
