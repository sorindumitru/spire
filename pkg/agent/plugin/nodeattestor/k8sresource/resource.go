package k8sresource

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName       = "k8s_resource"
	defaultTokenPath = "/var/run/secrets/tokens/spire-agent" //nolint: gosec // false positive
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

// New creates a new k8s_resource attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

// AttestorPlugin is a k8s_resource attestor plugin. It attests the agent using
// a projected service account token (like k8s_psat) and additionally declares a
// list of Kubernetes resources the agent's service account must be authorized to
// access. The server verifies that authorization via the SubjectAccessReview API.
type AttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *attestorConfig
}

// AttestorConfig holds configuration for AttestorPlugin
type AttestorConfig struct {
	// Cluster name where the agent lives
	Cluster string `hcl:"cluster"`
	// File path of PSAT
	TokenPath string `hcl:"token_path"`
	// Resources the agent's service account must be authorized to access
	Resources []ResourceHCLEntry `hcl:"resource"`
}

// ResourceHCLEntry is a single resource access check declared in the agent
// configuration. It mirrors the fields of k8s.RequestedResource.
type ResourceHCLEntry struct {
	Namespace   string `hcl:"namespace"`
	Verb        string `hcl:"verb"`
	Group       string `hcl:"group"`
	Version     string `hcl:"version"`
	Resource    string `hcl:"resource"`
	Subresource string `hcl:"subresource"`
	Name        string `hcl:"name"`
}

func buildConfig(_ catalog.CoreConfig, hclText string, status *pluginconf.Status) *attestorConfig {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if hclConfig.Cluster == "" {
		status.ReportError("missing required cluster block")
	}

	resources := make([]k8s.RequestedResource, 0, len(hclConfig.Resources))
	for i, r := range hclConfig.Resources {
		if r.Verb == "" {
			status.ReportErrorf("resource[%d] must have a verb", i)
		}
		// group is always required; resource, namespace and name are optional,
		// but a name requires a namespace.
		if r.Group == "" {
			status.ReportErrorf("resource[%d] must have a group", i)
		}
		if r.Name != "" && r.Namespace == "" {
			status.ReportErrorf("resource[%d] must have a namespace when name is set", i)
		}
		resources = append(resources, k8s.RequestedResource{
			Namespace:   r.Namespace,
			Verb:        r.Verb,
			Group:       r.Group,
			Version:     r.Version,
			Resource:    r.Resource,
			Subresource: r.Subresource,
			Name:        r.Name,
		})
	}

	newConfig := &attestorConfig{
		cluster:   hclConfig.Cluster,
		tokenPath: hclConfig.TokenPath,
		resources: resources,
	}

	if newConfig.tokenPath == "" {
		newConfig.tokenPath = getDefaultTokenPath()
	}

	return newConfig
}

type attestorConfig struct {
	cluster   string
	tokenPath string
	resources []k8s.RequestedResource
}

// AidAttestation loads the PSAT token from the configured path and sends it
// along with the declared resource list.
func (p *AttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	token, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to load token from %s: %v", config.tokenPath, err)
	}

	payload, err := json.Marshal(k8s.ResourceAttestationData{
		Cluster:   config.cluster,
		Token:     token,
		Resources: config.resources,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	})
}

// Configure decodes JSON config from request and populates AttestorPlugin with it
func (p *AttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (resp *configv1.ValidateResponse, err error) {
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

func loadTokenFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%q is empty", path)
	}
	return string(data), nil
}
