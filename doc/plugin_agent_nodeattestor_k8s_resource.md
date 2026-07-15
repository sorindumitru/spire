# Agent plugin: NodeAttestor "k8s_resource"

*Must be used in conjunction with the [server-side k8s_resource plugin](plugin_server_nodeattestor_k8s_resource.md)*

The `k8s_resource` plugin attests nodes running inside of Kubernetes. The agent
reads and provides the signed projected service account token (PSAT) to the
server, and additionally declares a list of Kubernetes resources that its service
account must be authorized to access. The
[server-side `k8s_resource` plugin](plugin_server_nodeattestor_k8s_resource.md)
verifies that authorization via the SubjectAccessReview API and, on success,
generates a SPIFFE ID on behalf of the agent of the form:

```xml
spiffe://<trust_domain>/spire/agent/k8s_resource/<cluster>/<pod_UID>
```

Because the agent identity is derived from the pod UID, this attestor supports
agents deployed as a **Deployment** with multiple replicas (including replicas
co-located on the same node), which is the typical setup for "broker" agents.

Attestation **fails closed**: if the server determines the service account is not
authorized for any of the declared resources, attestation fails.

The main configuration accepts the following values:

| Configuration | Description                                                                           | Default                               |
|---------------|---------------------------------------------------------------------------------------|---------------------------------------|
| `cluster`     | Name of the cluster. It must correspond to a cluster configured in the server plugin. |                                       |
| `token_path`  | Path to the projected service account token on disk                                   | "/var/run/secrets/tokens/spire-agent" |
| `resource`    | A repeated block declaring a resource the service account must be authorized to access | []                                    |

Each `resource` block accepts the following values, mirroring the Kubernetes
[ResourceAttributes](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/#SubjectAccessReviewSpec):

| Configuration       | Description                                                            |
|---------------------|-----------------------------------------------------------------------|
| `verb`              | The verb to check, e.g. `get`, `list`, `watch`, `create`, `update` (required) |
| `group`             | API group of the resource (required)                                  |
| `version`           | API version of the resource                                           |
| `resource`          | Resource type, e.g. `deployments` or a CRD plural (optional)          |
| `subresource`       | Subresource, e.g. `status`                                            |
| `namespace`         | Namespace of the resource (required when `name` is set)               |
| `name`              | Name of a specific resource instance                                  |

Validation rules for each block:

* `verb` is always required.
* `group` is required. `resource` is optional (a group-only entry authorizes the
  whole group); `namespace` and `name` are optional, but a `name` requires a
  `namespace`. (The empty core group is not expressible — every resource entry
  must name a group.)

Empty fields are omitted from the resulting selector, so no dangling separators
are produced (see the server plugin docs for the selector format).

A sample configuration:

```hcl
    NodeAttestor "k8s_resource" {
        plugin_data {
            cluster = "MyCluster"
            resource = [
                { verb = "get",  group = "apps", resource = "deployments", namespace = "app", name = "web" },
                { verb = "list", group = "apps", resource = "deployments", namespace = "app" },
                { verb = "impersonate-via-spire", group = "kustomize.toolkit.fluxcd.io", resource = "kustomizations" },
            ]
        }
    }
```

Its k8s volume definition:

```yaml
volumes:
    - name: spire-agent
      projected:
        sources:
        - serviceAccountToken:
            path: spire-agent
            expirationSeconds: 600
            audience: spire-server
```

And volume mount:

```yaml
volumeMounts:
    - mountPath: /var/run/secrets/tokens
      name: spire-agent
```

The agent's service account must be granted (via Kubernetes RBAC) access to every
declared resource; otherwise attestation fails. For example, to authorize the
sample configuration above:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app
  name: spire-broker
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["settings"]
  verbs: ["get"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: app
  name: spire-broker
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: spire-broker
subjects:
- kind: ServiceAccount
  name: spire-broker
  namespace: production
```

The agent should be deployed as a `Deployment` (rather than a `DaemonSet`), since
it does not need to run on every node.
