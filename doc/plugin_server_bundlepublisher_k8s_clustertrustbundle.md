# Server plugin: BundlePublisher "k8s_clustertrustbundle"

The `k8s_clustertrustbundle` plugin puts the X.509 authorities of the current trust bundle of the server
in a designated Kubernetes [ClusterTrustBundle](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles),
keeping it updated. The plugin supports configuring multiple clusters.

ClusterTrustBundles are cluster-scoped, readable by any authenticated principal, and can be mounted into pods
using `clusterTrustBundle` projected volumes.

> [!NOTE]
> ClusterTrustBundles only hold X.509 certificates in PEM format. JWT authorities are not published.

The plugin accepts the following configuration:

| Configuration | Description                                                                                       | Default |
|---------------|---------------------------------------------------------------------------------------------------|---------|
| `clusters`    | A map of clusters, keyed by an arbitrary ID, where the plugin publishes the current trust bundle. |         |

> [!WARNING]
> When `clusters` is empty, the plugin does not publish the bundle.

Each cluster in the main configuration has the following configuration options:

| Configuration           | Description                                                                                                                                                                                                                                                                                                    | Required | Default           |
|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|-------------------|
| clustertrustbundle_name | The name of the ClusterTrustBundle. When `signer_name` is set, it must be prefixed by the signer name with `/` replaced by `:`, followed by `:`. Otherwise, it must not contain `:`. Defaults to the trust domain name, prefixed as required when `signer_name` is set (e.g. `spiffe.io:spire:example.org`).   | No.      | Trust domain name |
| signer_name             | The signer to associate the ClusterTrustBundle with (`spec.signerName`).                                                                                                                                                                                                                                       | No.      |                   |
| api_version             | The `certificates.k8s.io` API version used to manage the ClusterTrustBundle, &lt;v1 &vert; v1beta1&gt;. Use `v1beta1` for clusters that don't serve the `v1` API yet.                                                                                                                                          | No.      | v1                |
| kubeconfig_path         | The path on disk to the kubeconfig containing configuration to enable interaction with the Kubernetes API server. If unset, in-cluster credentials will be used.                                                                                                                                               | No.      |                   |

## Configuring Kubernetes

To use this plugin, configure Kubernetes permissions for the SPIRE Server's Service Account:

- For in-cluster SPIRE servers: grant permissions to the Service Account running SPIRE.
- For out-of-cluster SPIRE servers: grant permissions to the Service Account specified in the kubeconfig.

The plugin uses the Kubernetes Apply operation to manage ClusterTrustBundles. This operation will create the
ClusterTrustBundle if it doesn't exist, or update it if it does.

### Required Permissions

The Service Account needs the following permissions on `clustertrustbundles` in the `certificates.k8s.io` API group:

- `get` (required for the Apply operation to read the current state)
- `patch` (required for the Apply operation to update resources)
- `create` (required if the ClusterTrustBundle doesn't exist)

When `signer_name` is set, the Service Account also needs the `attest` verb on the `signers` resource for the configured signer name.

### Example

In this example, assume that Service Account is `spire-server`.

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-clustertrustbundle
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["clustertrustbundles"]
  verbs: ["create", "get", "patch"]
  resourceNames: ["spiffe.io:spire:bundle"]
# Only required when signer_name is set
- apiGroups: ["certificates.k8s.io"]
  resources: ["signers"]
  verbs: ["attest"]
  resourceNames: ["spiffe.io/spire"]

---

kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spire-server-clustertrustbundle
subjects:
- kind: ServiceAccount
  name: spire-server
  namespace: spire
roleRef:
  kind: ClusterRole
  name: spire-server-clustertrustbundle
  apiGroup: rbac.authorization.k8s.io
```

> [!NOTE]
> The Apply operation uses Server-Side Apply (SSA) with a field manager name of `spire-bundlepublisher-k8s_clustertrustbundle`.

## Consuming the bundle

Workloads can mount the bundle using a projected volume:

```yaml
volumes:
- name: spire-bundle
  projected:
    sources:
    - clusterTrustBundle:
        name: example.org
        path: bundle.pem
```

When `signer_name` is used, select by signer instead:

```yaml
    - clusterTrustBundle:
        signerName: spiffe.io/spire
        labelSelector: {}
        path: bundle.pem
```

## Sample configuration

The following configuration keeps the local trust bundle updated in ClusterTrustBundles from two different clusters. The first cluster uses the default name, the trust domain name.

```hcl
    BundlePublisher "k8s_clustertrustbundle" {
        plugin_data {
            clusters = {
                "example-cluster-1" = {
                    kubeconfig_path = "/file/path/cluster-1"
                },
                "example-cluster-2" = {
                    clustertrustbundle_name = "spiffe.io:spire:bundle"
                    signer_name = "spiffe.io/spire"
                    api_version = "v1beta1"
                    kubeconfig_path = "/file/path/cluster-2"
                }
            }
        }
    }
```
