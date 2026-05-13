## MWS Certificate Manager

External Secrets Operator integrates with [MWS Certificate Manager](https://mws.ru/docs/cloud-platform/certmanager/general/whatis-cert-manager.html) for secure secret management.

### Authentication

We support authentication using an authorized key for service account. The service account and the authorized key could be created via MWS Console, see [documentation](https://mws.ru/docs/cloud-platform/iam/keys.html).

Alternatively, the service account and the authorized key could be generated via [mws cli](https://mws.ru/docs/cloud-platform/mws-cli/general/quickstart-mws-cli.html) using the following commands:

```bash
mws iam service-account create "iam/projects/{project}/serviceAccounts/{service-account}"

mws iam authorized-key create "iam/projects/{project}/serviceAccounts/{service-account}/authorizedKeys/{key-name}" --key-algorithm ES256
```

The authorized key will have the following format:

```json
{
  "keyId" : "projects/{project}/serviceAccounts/{service-account}/authorizedKeys/{key-name}",
  "privateKey" : "MEECAQ...6w==",
  "publicKey" : "MFkwEw...JA==",
  "algorithm" : "ES256"
}
```

To use the authorized key, create it as a regular Kubernetes Secret:

```bash
kubectl create secret generic mws-auth --from-file=./authorized-key
```

The created secret should be accessible as a SecretKeyRef.

### Provider definition

A provider for MWS Certificate Manager could be defined as an SecretStore, a reference to the authorized key should be passed in the `auth` object:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: mws-certificate-manager-store
spec:
  provider:
    mwscertificatemanager:
      auth:
        authorizedKeySecretRef:
          name: mws-auth
          key: authorized-key
```

### Creating an external secret

To create a kubernetes secret from the MWS Certificate Manager, create an ExternalSecret based on the SecretStore:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: mws-external-certificate
spec:
  secretStoreRef:
    name: mws-certificate-manager-store
    kind: SecretStore
  data:
  - secretKey: my-certificate
    remoteRef:
      key: my-certificate
```

By default the secret data will be a JSON object, for example:

```json
{"certificate":"...","privateKey":"...","chainedCert":"..."}
```

MWS Certificate Manager provider supports several properties:

- `certificate`, the certificate content
- `privateKey`, the private key of the certificate
- `chainedCert`, the fullchain certificate

The property could be selected in the secret definition:

```yaml
    remoteRef:
      key: my-certificate
      property: privateKey
```

When the property is selected, the secret will contain the target value without JSON serialization.
