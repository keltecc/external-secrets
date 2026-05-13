## MWS Secret Manager

External Secrets Operator integrates with [MWS Secret Manager](https://mws.ru/docs/cloud-platform/secret-manager/general/whatis-secret-manager.html) for secure secret management.

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

A provider for MWS Secret Manager could be defined as an SecretStore, a reference to the authorized key should be passed in the `auth` object:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: mws-secret-manager-store
spec:
  provider:
    mwssecretmanager:
      auth:
        authorizedKeySecretRef:
          name: mws-auth
          key: authorized-key
```

### Creating an external secret

To create a kubernetes secret from the MWS Secret Manager, create an ExternalSecret based on the SecretStore:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: mws-external-secret
spec:
  secretStoreRef:
    name: mws-secret-manager-store
    kind: SecretStore
  data:
  - secretKey: my-secret
    remoteRef:
      key: my-secret
      version: 1
      property: password
```

The secret will contain the value of the target property.

When the property is not defined, the secret will contain the JSON object containing all existing properties:

```json
{"username":"...","password":"..."}
```

When the version is not defined, the secret will contain the current version of the secret.
