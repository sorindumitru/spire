package k8sresource

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"

	// Add auth providers to authenticate to clusters to verify tokens
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const (
	pluginName = "k8s_resource"
)

var (
	defaultAudience = []string{"spire-server"}
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// AttestorConfig contains a map of clusters that uses cluster name as key
type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Array of allowed service accounts names
	// Attestation is denied if coming from a service account that is not in the list
	ServiceAccountAllowList []string `hcl:"service_account_allow_list"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, k8s apiserver audience will be used
	Audience *[]string `hcl:"audience"`

	// Kubernetes configuration file path
	// Used to create a k8s client to query the API server. If string is empty, in-cluster configuration is used
	KubeConfigFile string `hcl:"kube_config_file"`
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type clusterConfig struct {
	serviceAccounts map[string]bool
	audience        []string
	client          apiserver.Client
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *attestorConfig {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	if len(hclConfig.Clusters) < 1 {
		status.ReportInfo("No clusters configured, k8s_resource attestation is effectively disabled")
	}

	newConfig := &attestorConfig{
		trustDomain: coreConfig.TrustDomain.String(),
		clusters:    make(map[string]*clusterConfig),
	}

	for name, hclCluster := range hclConfig.Clusters {
		if len(hclCluster.ServiceAccountAllowList) == 0 {
			status.ReportErrorf("cluster %q configuration must have at least one service account allowed", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range hclCluster.ServiceAccountAllowList {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if hclCluster.Audience == nil {
			audience = defaultAudience
		} else {
			audience = *hclCluster.Audience
		}

		newConfig.clusters[name] = &clusterConfig{
			serviceAccounts: serviceAccounts,
			audience:        audience,
			client:          apiserver.New(hclCluster.KubeConfigFile),
		}
	}

	return newConfig
}

// AttestorPlugin is a k8s_resource node attestor plugin
type AttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *attestorConfig
	log    hclog.Logger
}

// New creates a new k8s_resource node attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

var _ nodeattestorv1.NodeAttestorServer = (*AttestorPlugin)(nil)

// SetLogger sets up plugin logging
func (p *AttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *AttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(k8s.ResourceAttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return status.Error(codes.InvalidArgument, "missing cluster in attestation data")
	}

	if attestationData.Token == "" {
		return status.Error(codes.InvalidArgument, "missing token in attestation data")
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return status.Errorf(codes.InvalidArgument, "not configured for cluster %q", attestationData.Cluster)
	}

	tokenStatus, err := cluster.client.ValidateToken(stream.Context(), attestationData.Token, cluster.audience)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to validate token with TokenReview API for cluster %q: %v", attestationData.Cluster, err)
	}

	if !tokenStatus.Authenticated {
		return status.Errorf(codes.PermissionDenied, "token not authenticated according to TokenReview API for cluster %q", attestationData.Cluster)
	}

	namespace, serviceAccountName, err := k8s.GetNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to parse username from token review status for cluster %q: %v", attestationData.Cluster, err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return status.Errorf(codes.PermissionDenied, "%q is not an allowed service account for cluster %q", fullServiceAccountName, attestationData.Cluster)
	}

	podName, err := k8s.GetPodNameFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod name from token review status for cluster %q: %v", attestationData.Cluster, err)
	}

	podUID, err := k8s.GetPodUIDFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod UID from token review status for cluster %q: %v", attestationData.Cluster, err)
	}

	// Build the base SubjectAccessReview identity once from the authenticated
	// token identity, then check each requested resource against it. Every
	// requested resource must be authorized (fail closed).
	baseSpec := subjectAccessReviewSpecFromToken(tokenStatus)
	for _, resource := range attestationData.Resources {
		spec := baseSpec
		spec.ResourceAttributes = &authzv1.ResourceAttributes{
			Namespace:   resource.Namespace,
			Verb:        resource.Verb,
			Group:       resource.Group,
			Version:     resource.Version,
			Resource:    resource.Resource,
			Subresource: resource.Subresource,
			Name:        resource.Name,
		}

		sarStatus, err := cluster.client.SubjectAccessReview(stream.Context(), spec)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to review access with SubjectAccessReview API for cluster %q: %v", attestationData.Cluster, err)
		}

		if !sarStatus.Allowed || sarStatus.Denied {
			return status.Errorf(codes.PermissionDenied, "service account %q is not authorized to access resource %s in cluster %q: %s",
				fullServiceAccountName, describeResource(resource), attestationData.Cluster, sarStatus.Reason)
		}
	}

	selectorValues := []string{
		k8s.MakeSelectorValue("cluster", attestationData.Cluster),
		k8s.MakeSelectorValue("agent_ns", namespace),
		k8s.MakeSelectorValue("agent_sa", serviceAccountName),
		k8s.MakeSelectorValue("agent_pod_name", podName),
		k8s.MakeSelectorValue("agent_pod_uid", podUID),
	}

	for _, resource := range attestationData.Resources {
		selectorValues = append(selectorValues, resourceSelectorValue(resource))
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    true,
				SpiffeId:       k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, podUID),
				SelectorValues: selectorValues,
			},
		},
	})
}

func (p *AttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// subjectAccessReviewSpecFromToken builds the subject identity portion of a
// SubjectAccessReview from the authenticated identity returned by TokenReview.
func subjectAccessReviewSpecFromToken(tokenStatus *authv1.TokenReviewStatus) authzv1.SubjectAccessReviewSpec {
	user := tokenStatus.User
	extra := make(map[string]authzv1.ExtraValue, len(user.Extra))
	for k, v := range user.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}
	return authzv1.SubjectAccessReviewSpec{
		User:   user.Username,
		Groups: user.Groups,
		UID:    user.UID,
		Extra:  extra,
	}
}

func resourceSelectorValue(resource k8s.RequestedResource) string {
	// Build the selector segment by segment so empty fields never produce
	// dangling separators (e.g. ":group/" or ":/name"). The namespace/name
	// segment is omitted entirely when no namespace is provided.
	values := []string{resource.Verb, joinPath(resource.Group, resource.Resource)}
	if resource.Namespace != "" {
		values = append(values, joinPath(resource.Namespace, resource.Name))
	}
	return k8s.MakeSelectorValue("resource", values...)
}

func describeResource(resource k8s.RequestedResource) string {
	desc := fmt.Sprintf("%s %s", resource.Verb, joinPath(resource.Group, resource.Resource))
	if resource.Namespace != "" {
		desc += " in " + joinPath(resource.Namespace, resource.Name)
	}
	return desc
}

// joinPath joins two path components with "/", skipping empty components so the
// result never has a leading or trailing slash.
func joinPath(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "/" + b
	}
}
