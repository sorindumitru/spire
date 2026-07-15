# Server plugin: NodeAttestor "k8s_resource"

*Must be used in conjunction with the [agent-side k8s_resource plugin](plugin_agent_nodeattestor_k8s_resource.md)*

The `k8s_resource` plugin attests nodes running inside of Kubernetes using a
projected service account token (PSAT), like the [`k8s_psat`](plugin_server_nodeattestor_k8s_psat.md)
plugin. In addition, the agent declares a list of Kubernetes resources it needs
access to, and the server verifies — via the Kubernetes
[SubjectAccessReview API](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/) —
that the agent's service account is actually authorized (through Kubernetes RBAC)
to access each of them. Kubernetes RBAC thus becomes the source of truth for what
the agent is allowed to represent, and the authorized resources are surfaced as
selectors on the agent's SPIFFE ID.

This is intended for "broker" style agents that are deployed as a **Deployment**
(not a DaemonSet) — there is no assumption of one agent per node, and multiple
replicas may run on the same node. For that reason the agent SPIFFE ID is derived
from the **pod UID** (unique per replica) rather than the node UID:

```xml
spiffe://<trust_domain>/spire/agent/k8s_resource/<cluster>/<pod UID>
```

The token is validated with the Kubernetes
[Token Review API](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#tokenreview-v1-authentication-k8s-io),
which also provides the namespace, service account name, pod name and pod UID
used to build selectors. The authenticated identity returned by the Token Review
API (user, groups, uid and extra) is passed through to each SubjectAccessReview
so that RBAC bound to groups is honored.

Attestation **fails closed**: if any declared resource is denied (or not
explicitly allowed) by SubjectAccessReview, attestation fails and no SVID is
issued. Unlike `k8s_psat`, this plugin does not query the pods or nodes APIs.

The server does not need to be running in Kubernetes in order to perform node
attestation, and can be configured to attest nodes running in multiple clusters.

The main configuration accepts the following values:

| Configuration | Description                                                                       | Default |
|---------------|-----------------------------------------------------------------------------------|---------|
| `clusters`    | A map of clusters, keyed by an arbitrary ID, that are authorized for attestation. |         |

> [!WARNING]
> When `clusters` is empty, no clusters are authorized for attestation.

Each cluster in the main configuration requires the following configuration:

| Configuration                | Description                                                                                                                                                                                                                                                                 | Default          |
|------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------|
| `service_account_allow_list` | A list of service account names, qualified by namespace (for example, "default:blog" or "production:web") to allow for node attestation. Attestation will be rejected for tokens bound to service accounts that aren't in the allow list.                                    |                  |
| `audience`                   | Audience for token validation. If it is set to an empty array (`[]`), Kubernetes API server audience is used                                                                                                                                                                | ["spire-server"] |
| `kube_config_file`           | Path to a k8s configuration file for API Server authentication. A kubernetes configuration file must be specified if SPIRE server runs outside of the k8s cluster. If empty, SPIRE server is assumed to be running inside the cluster and in-cluster configuration is used. | ""               |

A sample configuration for SPIRE server running inside a Kubernetes cluster:

```hcl
    NodeAttestor "k8s_resource" {
        plugin_data {
            clusters = {
                "MyCluster" = {
                    service_account_allow_list = ["production:spire-broker"]
                }
            }
        }
    }
```

The Kubernetes user defined in the kube config file (or the service account of an
in-cluster server) needs to be able to create Token Reviews and Subject Access
Reviews:

```yaml
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
```

Binding the built-in `system:auth-delegator` ClusterRole to the server's service
account also grants both permissions.

This plugin generates the following selectors:

| Selector                      | Example                                                          | Description                                                                     |
|-------------------------------|------------------------------------------------------------------|---------------------------------------------------------------------------------|
| `k8s_resource:cluster`        | `k8s_resource:cluster:MyCluster`                                 | Name of the cluster (from the plugin config) used to verify the token signature |
| `k8s_resource:agent_ns`       | `k8s_resource:agent_ns:production`                               | Namespace that the agent is running under                                        |
| `k8s_resource:agent_sa`       | `k8s_resource:agent_sa:spire-broker`                            | Service Account the agent is running under                                       |
| `k8s_resource:agent_pod_name` | `k8s_resource:agent_pod_name:spire-broker-v5wgr`               | Name of the pod in which the agent is running                                    |
| `k8s_resource:agent_pod_uid`  | `k8s_resource:agent_pod_uid:79261129-6b60-11e9-9054-0800277ac80f` | UID of the pod in which the agent is running                                     |
| `k8s_resource:resource`       | `k8s_resource:resource:get:apps/deployments:app/web`            | An authorized resource access, as `verb:group[/resource][:namespace[/name]]`     |

One `resource` selector is generated per declared resource, in the order declared
by the agent. The selector is built from whatever fields are provided, and empty
fields are omitted so no dangling separators appear:

* `group` only → `resource:<verb>:<group>`
* `group` + `resource` → `resource:<verb>:<group>/<resource>`
* add a `namespace` → `...:<namespace>`
* add a `namespace` and `name` → `...:<namespace>/<name>`

The agent config requires `group` on every resource entry and requires a
`namespace` whenever a `name` is set, so the group and name segments are never
malformed.
