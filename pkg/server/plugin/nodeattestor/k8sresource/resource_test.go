package k8sresource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"google.golang.org/grpc/codes"
	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	fooSigner       jose.Signer
	attestor        nodeattestor.NodeAttestor
	apiServerClient *fakeAPIServerClient
}

type TokenData struct {
	namespace          string
	serviceAccountName string
	podName            string
	podUID             string
	audience           []string
	notBefore          time.Time
	expiry             time.Time
}

func (s *AttestorSuite) SetupSuite() {
	var err error
	s.fooSigner, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       testkey.MustRSA2048(),
	}, nil)
	s.Require().NoError(err)
}

func (s *AttestorSuite) SetupTest() {
	s.attestor = s.loadPlugin()
}

func (s *AttestorSuite) TestAttestFailsWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor)
	s.attestor = attestor
	s.requireAttestError([]byte("{"), codes.FailedPrecondition, "nodeattestor(k8s_resource): not configured")
}

func (s *AttestorSuite) TestAttestFailsWithMalformedPayload() {
	s.requireAttestError([]byte("{"), codes.InvalidArgument, "nodeattestor(k8s_resource): failed to unmarshal data payload")
}

func (s *AttestorSuite) TestAttestFailsWithNoClusterInPayload() {
	s.requireAttestError(s.makePayload("", "TOKEN"),
		codes.InvalidArgument,
		"nodeattestor(k8s_resource): missing cluster in attestation data")
}

func (s *AttestorSuite) TestAttestFailsWithNoTokenInPayload() {
	s.requireAttestError(s.makePayload("FOO", ""),
		codes.InvalidArgument,
		"nodeattestor(k8s_resource): missing token in attestation data")
}

func (s *AttestorSuite) TestAttestFailsIfClusterNotConfigured() {
	s.requireAttestError(s.makePayload("CLUSTER", "blah"),
		codes.InvalidArgument,
		`nodeattestor(k8s_resource): not configured for cluster "CLUSTER"`)
}

func (s *AttestorSuite) TestAttestFailsIfTokenReviewAPIFails() {
	tokenData := defaultTokenData()
	token := s.signToken(s.fooSigner, tokenData)
	s.requireAttestError(s.makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_resource): unable to validate token with TokenReview API")
}

func (s *AttestorSuite) TestAttestFailsIfTokenNotAuthenticated() {
	tokenData := defaultTokenData()
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, false, defaultAudience))
	s.requireAttestError(s.makePayload("FOO", token),
		codes.PermissionDenied,
		"nodeattestor(k8s_resource): token not authenticated")
}

func (s *AttestorSuite) TestAttestFailsWithMissingServiceAccountNameClaim() {
	tokenData := &TokenData{namespace: "NS1", podName: "PODNAME", podUID: "PODUID"}
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	s.requireAttestError(s.makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_resource): fail to parse username from token review status")
}

func (s *AttestorSuite) TestAttestFailsWithMissingPodUIDClaim() {
	tokenData := &TokenData{namespace: "NS1", serviceAccountName: "SA1", podName: "PODNAME"}
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	s.requireAttestError(s.makePayload("FOO", token),
		codes.Internal,
		"nodeattestor(k8s_resource): fail to get pod UID from token review status")
}

func (s *AttestorSuite) TestAttestFailsIfServiceAccountNotAllowed() {
	tokenData := &TokenData{namespace: "NS1", serviceAccountName: "SERVICEACCOUNTNAME", podName: "PODNAME", podUID: "PODUID"}
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	s.requireAttestError(s.makePayload("FOO", token),
		codes.PermissionDenied,
		`nodeattestor(k8s_resource): "NS1:SERVICEACCOUNTNAME" is not an allowed service account`)
}

func (s *AttestorSuite) TestAttestFailsIfSubjectAccessReviewAPIFails() {
	tokenData := defaultTokenData()
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	s.apiServerClient.sarError = errors.New("boom")
	s.requireAttestError(s.makePayload("FOO", token, configMapResource()),
		codes.Internal,
		"nodeattestor(k8s_resource): unable to review access with SubjectAccessReview API")
}

func (s *AttestorSuite) TestAttestFailsIfResourceDenied() {
	tokenData := defaultTokenData()
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	s.apiServerClient.SetSARResult(configMapResource(), authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: true, Reason: "nope"})
	s.requireAttestError(s.makePayload("FOO", token, configMapResource()),
		codes.PermissionDenied,
		"is not authorized to access resource")
}

func (s *AttestorSuite) TestAttestFailsIfOneOfMultipleResourcesDenied() {
	tokenData := defaultTokenData()
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	allowed := configMapResource()
	denied := sat_common.RequestedResource{Verb: "list", Group: "apps", Resource: "deployments", Namespace: "app"}
	s.apiServerClient.SetSARResult(allowed, authzv1.SubjectAccessReviewStatus{Allowed: true})
	s.apiServerClient.SetSARResult(denied, authzv1.SubjectAccessReviewStatus{Allowed: false})
	s.requireAttestError(s.makePayload("FOO", token, allowed, denied),
		codes.PermissionDenied,
		"is not authorized to access resource")
}

func (s *AttestorSuite) TestAttestSuccess() {
	tokenData := &TokenData{namespace: "NS1", serviceAccountName: "SA1", podName: "PODNAME-1", podUID: "PODUID-1"}
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	resource := configMapResource()
	s.apiServerClient.SetSARResult(resource, authzv1.SubjectAccessReviewStatus{Allowed: true})

	result, err := s.attestor.Attest(context.Background(), s.makePayload("FOO", token, resource), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Equal("spiffe://example.org/spire/agent/k8s_resource/FOO/PODUID-1", result.AgentID)
	s.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_resource", Value: "cluster:FOO"},
		{Type: "k8s_resource", Value: "agent_ns:NS1"},
		{Type: "k8s_resource", Value: "agent_sa:SA1"},
		{Type: "k8s_resource", Value: "agent_pod_name:PODNAME-1"},
		{Type: "k8s_resource", Value: "agent_pod_uid:PODUID-1"},
		{Type: "k8s_resource", Value: "resource:get:configmaps:app/settings"},
	}, result.Selectors)

	// Verify the SubjectAccessReview spec carried the authenticated identity.
	s.Require().Len(s.apiServerClient.gotSpecs, 1)
	gotSpec := s.apiServerClient.gotSpecs[0]
	s.Equal("system:serviceaccount:NS1:SA1", gotSpec.User)
	s.Equal([]string{"system:authenticated"}, gotSpec.Groups)
	s.Equal("UID-1", gotSpec.UID)
	s.Require().NotNil(gotSpec.ResourceAttributes)
	s.Equal("configmaps", gotSpec.ResourceAttributes.Resource)
	s.Equal("get", gotSpec.ResourceAttributes.Verb)
	s.Equal("app", gotSpec.ResourceAttributes.Namespace)
	s.Equal("settings", gotSpec.ResourceAttributes.Name)
}

func (s *AttestorSuite) TestAttestSuccessWithNoResources() {
	tokenData := &TokenData{namespace: "NS1", serviceAccountName: "SA1", podName: "PODNAME-1", podUID: "PODUID-1"}
	token := s.signToken(s.fooSigner, tokenData)
	s.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))

	result, err := s.attestor.Attest(context.Background(), s.makePayload("FOO", token), expectNoChallenge)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.Require().Len(result.Selectors, 5)
	s.Require().Empty(s.apiServerClient.gotSpecs)
}

func (s *AttestorSuite) TestConfigure() {
	doConfig := func(coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(s.T(), BuiltIn(), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	err := doConfig(coreConfig, "blah")
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "plugin configuration is malformed")

	err = doConfig(catalog.CoreConfig{}, "")
	s.RequireGRPCStatus(err, codes.InvalidArgument, "server core configuration must contain trust_domain")

	err = doConfig(coreConfig, "")
	s.Require().NoError(err)

	err = doConfig(coreConfig, `clusters = {
			"FOO" = {}
		}`)
	s.RequireGRPCStatus(err, codes.InvalidArgument, `cluster "FOO" configuration must have at least one service account allowed`)
}

func defaultTokenData() *TokenData {
	return &TokenData{namespace: "NS1", serviceAccountName: "SA1", podName: "PODNAME", podUID: "PODUID"}
}

func configMapResource() sat_common.RequestedResource {
	return sat_common.RequestedResource{Verb: "get", Resource: "configmaps", Namespace: "app", Name: "settings"}
}

func (s *AttestorSuite) signToken(signer jose.Signer, tokenData *TokenData) string {
	if tokenData.notBefore.IsZero() {
		tokenData.notBefore = time.Now().Add(-time.Minute)
	}
	if tokenData.expiry.IsZero() {
		tokenData.expiry = time.Now().Add(time.Minute)
	}

	claims := sat_common.PSATClaims{}
	claims.NotBefore = jwt.NewNumericDate(tokenData.notBefore)
	claims.Expiry = jwt.NewNumericDate(tokenData.expiry)
	claims.Audience = tokenData.audience
	claims.K8s.Namespace = tokenData.namespace
	claims.K8s.ServiceAccount.Name = tokenData.serviceAccountName
	claims.K8s.Pod.Name = tokenData.podName
	claims.K8s.Pod.UID = tokenData.podUID

	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.Serialize()
	s.Require().NoError(err)
	return token
}

func (s *AttestorSuite) loadPlugin() nodeattestor.NodeAttestor {
	attestor := New()
	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(attestor), v1, plugintest.Configure(`
		clusters = {
			"FOO" = {
				service_account_allow_list = ["NS1:SA1"]
				kube_config_file = ""
			}
			"BAR" = {
				service_account_allow_list = ["NS2:SA2"]
				kube_config_file = ""
				audience = ["AUDIENCE"]
			}
		}
	`), plugintest.CoreConfig(catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}))

	s.apiServerClient = newFakeAPIServerClient()
	attestor.config.clusters["FOO"].client = s.apiServerClient
	attestor.config.clusters["BAR"].client = s.apiServerClient
	return v1
}

func (s *AttestorSuite) requireAttestError(payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.RequireGRPCStatusContains(err, expectCode, expectMsg)
	s.Require().Nil(result)
}

func (s *AttestorSuite) makePayload(cluster, token string, resources ...sat_common.RequestedResource) []byte {
	payload, err := json.Marshal(sat_common.ResourceAttestationData{
		Cluster:   cluster,
		Token:     token,
		Resources: resources,
	})
	s.Require().NoError(err)
	return payload
}

func expectNoChallenge(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}

func createTokenStatus(tokenData *TokenData, authenticated bool, audience []string) *authv1.TokenReviewStatus {
	values := make(map[string]authv1.ExtraValue)
	values["authentication.kubernetes.io/pod-name"] = authv1.ExtraValue([]string{tokenData.podName})
	values["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue([]string{tokenData.podUID})
	return &authv1.TokenReviewStatus{
		Authenticated: authenticated,
		User: authv1.UserInfo{
			Username: fmt.Sprintf("system:serviceaccount:%s:%s", tokenData.namespace, tokenData.serviceAccountName),
			UID:      "UID-1",
			Groups:   []string{"system:authenticated"},
			Extra:    values,
		},
		Audiences: audience,
	}
}

type fakeAPIServerClient struct {
	status     map[string]*authv1.TokenReviewStatus
	sarResults map[string]authzv1.SubjectAccessReviewStatus
	sarError   error
	gotSpecs   []authzv1.SubjectAccessReviewSpec
}

func newFakeAPIServerClient() *fakeAPIServerClient {
	return &fakeAPIServerClient{
		status:     make(map[string]*authv1.TokenReviewStatus),
		sarResults: make(map[string]authzv1.SubjectAccessReviewStatus),
	}
}

func (c *fakeAPIServerClient) SetTokenStatus(token string, status *authv1.TokenReviewStatus) {
	c.status[token] = status
}

func (c *fakeAPIServerClient) SetSARResult(resource sat_common.RequestedResource, status authzv1.SubjectAccessReviewStatus) {
	c.sarResults[resourceSelectorValue(resource)] = status
}

func (c *fakeAPIServerClient) GetNode(context.Context, string) (*corev1.Node, error) {
	return nil, errors.New("GetNode is not expected")
}

func (c *fakeAPIServerClient) GetPod(context.Context, string, string) (*corev1.Pod, error) {
	return nil, errors.New("GetPod is not expected")
}

func (c *fakeAPIServerClient) ValidateToken(_ context.Context, token string, _ []string) (*authv1.TokenReviewStatus, error) {
	status, ok := c.status[token]
	if !ok {
		return nil, errors.New("no status configured by test for token")
	}
	return status, nil
}

func (c *fakeAPIServerClient) SubjectAccessReview(_ context.Context, spec authzv1.SubjectAccessReviewSpec) (*authzv1.SubjectAccessReviewStatus, error) {
	if c.sarError != nil {
		return nil, c.sarError
	}
	c.gotSpecs = append(c.gotSpecs, spec)
	key := sarSpecKey(spec)
	result, ok := c.sarResults[key]
	if !ok {
		return &authzv1.SubjectAccessReviewStatus{Allowed: false, Reason: "no result configured by test"}, nil
	}
	return &result, nil
}

func sarSpecKey(spec authzv1.SubjectAccessReviewSpec) string {
	ra := spec.ResourceAttributes
	return resourceSelectorValue(sat_common.RequestedResource{
		Namespace: ra.Namespace,
		Verb:      ra.Verb,
		Group:     ra.Group,
		Resource:  ra.Resource,
		Name:      ra.Name,
	})
}
