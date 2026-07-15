package k8sresource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
)

var (
	sampleKey     = testkey.MustRSA2048()
	streamBuilder = nodeattestortest.ServerStream(pluginName)
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir string
}

func (s *AttestorSuite) SetupTest() {
	s.dir = s.TempDir()
}

func (s *AttestorSuite) TestAttestNotConfigured() {
	na := s.loadPlugin()
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.FailedPrecondition, "nodeattestor(k8s_resource): not configured")
}

func (s *AttestorSuite) TestAttestNoToken() {
	na := s.loadPluginWithTokenPath(s.joinPath("token"))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_resource): unable to load token from")
}

func (s *AttestorSuite) TestAttestEmptyToken() {
	na := s.loadPluginWithTokenPath(s.writeValue("token", ""))
	err := na.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "nodeattestor(k8s_resource): unable to load token from")
}

func (s *AttestorSuite) TestAttestSuccess() {
	token, err := createPSAT("NAMESPACE", "POD-NAME")
	s.Require().NoError(err)

	na := s.loadPluginWithTokenPath(s.writeValue("token", token))

	expectPayload := fmt.Appendf(nil,
		`{"cluster":"production","token":"%s","resources":[{"namespace":"app","verb":"get","group":"apps","resource":"deployments","name":"settings"}]}`,
		token)
	err = na.Attest(context.Background(), streamBuilder.ExpectAndBuild(expectPayload))
	s.Require().NoError(err)
}

func (s *AttestorSuite) TestConfigure() {
	var err error

	// malformed configuration
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure("malformed"),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing cluster
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure(""),
	)
	s.RequireGRPCStatus(err, codes.InvalidArgument, "missing required cluster block")

	// resource missing verb
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure(`
			cluster = "production"
			resource = [{ group = "apps", resource = "deployments" }]
		`),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "resource[0] must have a verb")

	// resource missing group
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure(`
			cluster = "production"
			resource = [{ verb = "get", resource = "configmaps" }]
		`),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "resource[0] must have a group")

	// name without namespace
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure(`
			cluster = "production"
			resource = [{ verb = "get", group = "apps", resource = "deployments", name = "settings" }]
		`),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "resource[0] must have a namespace when name is set")

	// success: full resource attributes
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure(`
			cluster = "production"
			resource = [{ verb = "get", group = "apps", resource = "deployments", namespace = "app", name = "settings" }]
		`),
	)
	s.Require().NoError(err)

	// success: group only (resource, namespace and name are optional)
	s.loadPlugin(plugintest.CaptureConfigureError(&err),
		coreConfig(),
		plugintest.Configure(`
			cluster = "production"
			resource = [{ verb = "list", group = "apps" }]
		`),
	)
	s.Require().NoError(err)
}

func (s *AttestorSuite) loadPluginWithTokenPath(tokenPath string) nodeattestor.NodeAttestor {
	return s.loadPlugin(
		coreConfig(),
		plugintest.Configuref(`
			cluster = "production"
			token_path = %q
			resource = [{ verb = "get", group = "apps", resource = "deployments", namespace = "app", name = "settings" }]
		`, tokenPath),
	)
}

func (s *AttestorSuite) loadPlugin(options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), na, options...)
	return na
}

func (s *AttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *AttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0o755)
	s.Require().NoError(err)
	err = os.WriteFile(valuePath, []byte(data), 0o600)
	s.Require().NoError(err)
	return valuePath
}

func coreConfig() plugintest.Option {
	return plugintest.CoreConfig(catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	})
}

// Creates a PSAT using the given namespace and podName (just for testing)
func createPSAT(namespace, podName string) (string, error) {
	signer, err := createSigner()
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(signer)

	claims := sat_common.PSATClaims{}
	claims.K8s.Namespace = namespace
	claims.K8s.Pod.Name = podName
	builder = builder.Claims(claims)

	token, err := builder.Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func createSigner() (jose.Signer, error) {
	sampleSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sampleKey,
	}, nil)
	if err != nil {
		return nil, err
	}

	return sampleSigner, nil
}
