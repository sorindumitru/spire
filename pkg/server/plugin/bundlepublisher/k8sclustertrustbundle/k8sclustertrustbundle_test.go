package k8sclustertrustbundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		newClientErr error
		trustDomain  string
		hclConfig    string
		expectCode   codes.Code
		expectMsg    string
		expectCfg    *Config
	}{
		{
			name: "success",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "spire-bundle"
						api_version = "v1beta1"
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "spire-bundle",
						APIVersion:             "v1beta1",
						KubeConfigPath:         "/path/to/kubeconfig",
					},
				},
			},
		},
		{
			name: "defaults to v1",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "spire-bundle"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "spire-bundle",
						APIVersion:             "v1",
					},
				},
			},
		},
		{
			name: "success with signer name",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "example.org:spire:bundle"
						signer_name = "example.org/spire"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "example.org:spire:bundle",
						SignerName:             "example.org/spire",
						APIVersion:             "v1",
					},
				},
			},
		},
		{
			name: "multiple clusters",
			hclConfig: `
				clusters = {
					"cluster-1" = {
						clustertrustbundle_name = "spire-bundle"
						kubeconfig_path = "/path/to/kubeconfig-1"
					}
					"cluster-2" = {
						clustertrustbundle_name = "spire-bundle"
						api_version = "v1beta1"
						kubeconfig_path = "/path/to/kubeconfig-2"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"cluster-1": {
						ClusterTrustBundleName: "spire-bundle",
						APIVersion:             "v1",
						KubeConfigPath:         "/path/to/kubeconfig-1",
					},
					"cluster-2": {
						ClusterTrustBundleName: "spire-bundle",
						APIVersion:             "v1beta1",
						KubeConfigPath:         "/path/to/kubeconfig-2",
					},
				},
			},
		},
		{
			name:      "no clusters",
			hclConfig: "",
			expectCfg: &Config{},
		},
		{
			name: "defaults name to trust domain",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						kubeconfig_path = "/path/to/kubeconfig"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "example.org",
						APIVersion:             "v1",
						KubeConfigPath:         "/path/to/kubeconfig",
					},
				},
			},
		},
		{
			name: "defaults name to signer prefixed trust domain",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						signer_name = "spiffe.io/spire"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "spiffe.io:spire:example.org",
						SignerName:             "spiffe.io/spire",
						APIVersion:             "v1",
					},
				},
			},
		},
		{
			name:        "trust domain not usable as default name",
			trustDomain: "example_org",
			hclConfig: `
				clusters = {
					"test-cluster" = {}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "trust domain \"example_org\" can't be used as the default clustertrustbundle name in cluster \"test-cluster\", set clustertrustbundle_name",
		},
		{
			name:        "explicit name with trust domain not usable as default name",
			trustDomain: "example_org",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "spire-bundle"
					}
				}
			`,
			expectCfg: &Config{
				Clusters: map[string]*Cluster{
					"test-cluster": {
						ClusterTrustBundleName: "spire-bundle",
						APIVersion:             "v1",
					},
				},
			},
		},
		{
			name: "unsupported api version",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "spire-bundle"
						api_version = "v1alpha1"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "unsupported api_version \"v1alpha1\" in cluster \"test-cluster\"",
		},
		{
			name: "name without signer prefix",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "spire-bundle"
						signer_name = "example.org/spire"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "clustertrustbundle name \"spire-bundle\" in cluster \"test-cluster\" must have prefix \"example.org:spire:\" when signer_name is set",
		},
		{
			name: "name with colon and no signer",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "example.org:spire:bundle"
					}
				}
			`,
			expectCode: codes.InvalidArgument,
			expectMsg:  "clustertrustbundle name \"example.org:spire:bundle\" in cluster \"test-cluster\" must not contain ':' when signer_name is not set",
		},
		{
			name: "client creation error",
			hclConfig: `
				clusters = {
					"test-cluster" = {
						clustertrustbundle_name = "spire-bundle"
					}
				}
			`,
			newClientErr: errors.New("client error"),
			expectCode:   codes.Internal,
			expectMsg:    "failed to create Kubernetes client for cluster \"test-cluster\": client error",
		},
		{
			name:       "invalid config",
			hclConfig:  "invalid config",
			expectCode: codes.InvalidArgument,
			expectMsg:  "unable to decode configuration",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trustDomain := tt.trustDomain
			if trustDomain == "" {
				trustDomain = "example.org"
			}

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString(trustDomain),
				}),
				plugintest.Configure(tt.hclConfig),
			}

			newClient := func(kubeconfigPath string) (kubernetesClient, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return &fakeClient{}, nil
			}
			p := newPlugin(newClient)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectMsg != "" {
				require.Nil(t, p.config)
				return
			}

			require.Len(t, p.config.Clusters, len(tt.expectCfg.Clusters))
			for id, cluster := range p.config.Clusters {
				expected := tt.expectCfg.Clusters[id]
				require.NotNil(t, expected)
				require.Equal(t, expected.ClusterTrustBundleName, cluster.ClusterTrustBundleName)
				require.Equal(t, expected.SignerName, cluster.SignerName)
				require.Equal(t, expected.APIVersion, cluster.APIVersion)
				require.Equal(t, expected.KubeConfigPath, cluster.KubeConfigPath)
				require.NotNil(t, cluster.k8sClient)
			}
		})
	}
}

func TestPublishBundle(t *testing.T) {
	testBundle := getTestBundle(t)
	hclConfig := `
		clusters = {
			"test-cluster" = {
				clustertrustbundle_name = "spire-bundle"
			}
		}
	`

	for _, tt := range []struct {
		name string

		hclConfig  string
		expectCode codes.Code
		expectMsg  string
		bundle     *types.Bundle
		applyErr   error
	}{
		{
			name:      "success",
			bundle:    testBundle,
			hclConfig: hclConfig,
		},
		{
			name:       "apply error",
			bundle:     testBundle,
			hclConfig:  hclConfig,
			applyErr:   errors.New("apply error"),
			expectCode: codes.Internal,
			expectMsg:  "failed to apply ClusterTrustBundle for cluster \"test-cluster\": apply error",
		},
		{
			name:       "missing bundle",
			hclConfig:  hclConfig,
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing bundle in request",
		},
		{
			name:       "no X.509 authorities",
			bundle:     &types.Bundle{TrustDomain: "example.org"},
			hclConfig:  hclConfig,
			expectCode: codes.InvalidArgument,
			expectMsg:  "bundle has no X.509 authorities",
		},
		{
			name:       "not configured",
			expectCode: codes.FailedPrecondition,
			expectMsg:  "not configured",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			var options []plugintest.Option
			if tt.hclConfig != "" {
				options = []plugintest.Option{
					plugintest.CaptureConfigureError(&err),
					plugintest.CoreConfig(catalog.CoreConfig{
						TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
					}),
					plugintest.Configure(tt.hclConfig),
				}
			}
			client := &fakeClient{applyErr: tt.applyErr}

			p := newPlugin(func(string) (kubernetesClient, error) { return client, nil })
			plugintest.Load(t, builtin(p), nil, options...)
			require.NoError(t, err)

			resp, err := p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{
				Bundle: tt.bundle,
			})

			if tt.expectMsg != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, expectedPEM(t, tt.bundle), client.writtenBytes["spire-bundle"])
		})
	}
}

func TestPublishMultiple(t *testing.T) {
	hclConfig := `
		clusters = {
			"test-cluster" = {
				clustertrustbundle_name = "spire-bundle"
			}
		}`

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(hclConfig),
	}

	client := &fakeClient{}
	p := newPlugin(func(string) (kubernetesClient, error) { return client, nil })
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	bundle.SequenceNumber = 1
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{Bundle: bundle})
	require.NoError(t, err)
	require.Equal(t, 1, client.updateCount)

	// Same bundle is not published again.
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{Bundle: bundle})
	require.NoError(t, err)
	require.Equal(t, 1, client.updateCount)

	bundle = getTestBundle(t)
	bundle.SequenceNumber = 2
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{Bundle: bundle})
	require.NoError(t, err)
	require.Equal(t, 2, client.updateCount)
}

func TestPublishRetriesAfterFailure(t *testing.T) {
	hclConfig := `
		clusters = {
			"test-cluster" = {
				clustertrustbundle_name = "spire-bundle"
			}
		}`

	var err error
	options := []plugintest.Option{
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(hclConfig),
	}

	client := &fakeClient{applyErr: errors.New("apply error")}
	p := newPlugin(func(string) (kubernetesClient, error) { return client, nil })
	plugintest.Load(t, builtin(p), nil, options...)
	require.NoError(t, err)

	bundle := getTestBundle(t)
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{Bundle: bundle})
	require.Error(t, err)

	client.applyErr = nil
	_, err = p.PublishBundle(t.Context(), &bundlepublisherv1.PublishBundleRequest{Bundle: bundle})
	require.NoError(t, err)
	require.Equal(t, 1, client.updateCount)
}

func TestApplyClusterTrustBundle(t *testing.T) {
	pemData := expectedPEM(t, getTestBundle(t))

	for _, tt := range []struct {
		name       string
		apiVersion string
		signerName string
		ctbName    string
		expectErr  string
	}{
		{
			name:       "v1",
			apiVersion: apiVersionV1,
			ctbName:    "spire-bundle",
		},
		{
			name:       "v1 with signer",
			apiVersion: apiVersionV1,
			signerName: "example.org/spire",
			ctbName:    "example.org:spire:bundle",
		},
		{
			name:       "v1beta1",
			apiVersion: apiVersionV1beta1,
			ctbName:    "spire-bundle",
		},
		{
			name:       "v1beta1 with signer",
			apiVersion: apiVersionV1beta1,
			signerName: "example.org/spire",
			ctbName:    "example.org:spire:bundle",
		},
		{
			name:       "unsupported api version",
			apiVersion: "v1alpha1",
			ctbName:    "spire-bundle",
			expectErr:  "unsupported api version \"v1alpha1\"",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewClientset()
			c := &k8sClient{clientset: clientset}
			cluster := &Cluster{
				ClusterTrustBundleName: tt.ctbName,
				SignerName:             tt.signerName,
				APIVersion:             tt.apiVersion,
			}

			err := c.ApplyClusterTrustBundle(t.Context(), cluster, pemData)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)

			// Applying again updates the existing object.
			require.NoError(t, c.ApplyClusterTrustBundle(t.Context(), cluster, pemData))

			var trustBundle, signerName string
			switch tt.apiVersion {
			case apiVersionV1:
				ctb, err := clientset.CertificatesV1().ClusterTrustBundles().Get(t.Context(), tt.ctbName, metav1.GetOptions{})
				require.NoError(t, err)
				trustBundle, signerName = ctb.Spec.TrustBundle, ctb.Spec.SignerName
			case apiVersionV1beta1:
				ctb, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), tt.ctbName, metav1.GetOptions{})
				require.NoError(t, err)
				trustBundle, signerName = ctb.Spec.TrustBundle, ctb.Spec.SignerName
			}
			require.Equal(t, string(pemData), trustBundle)
			require.Equal(t, tt.signerName, signerName)
		})
	}
}

func TestBuiltIn(t *testing.T) {
	p := BuiltIn()
	require.NotNil(t, p)
	require.Equal(t, pluginName, p.Name)
}

func TestValidate(t *testing.T) {
	p := New()
	require.NotNil(t, p)

	for _, tt := range []struct {
		name        string
		req         *configv1.ValidateRequest
		expectValid bool
		expectNotes []string
	}{
		{
			name: "valid configuration",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: "example.org",
				},
				HclConfiguration: `
					clusters = {
						"test-cluster" = {
							clustertrustbundle_name = "spire-bundle"
							kubeconfig_path = "/path/to/kubeconfig"
						}
					}`,
			},
			expectValid: true,
		},
		{
			name: "note about no clusters",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: "example.org",
				},
			},
			expectValid: true,
			expectNotes: []string{"No clusters configured, bundle will not be published"},
		},
		{
			name: "missing trust domain",
			req: &configv1.ValidateRequest{
				CoreConfiguration: &configv1.CoreConfiguration{},
			},
			expectNotes: []string{
				"server core configuration must contain trust_domain",
				"No clusters configured, bundle will not be published",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Validate(t.Context(), tt.req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, tt.expectValid, resp.Valid)
			if tt.expectNotes != nil {
				require.Equal(t, tt.expectNotes, resp.Notes)
			}
		})
	}
}

type fakeClient struct {
	applyErr     error
	updateCount  int
	writtenBytes map[string][]byte
}

func (c *fakeClient) ApplyClusterTrustBundle(_ context.Context, cluster *Cluster, pemData []byte) error {
	if c.applyErr != nil {
		return c.applyErr
	}

	if c.writtenBytes == nil {
		c.writtenBytes = make(map[string][]byte)
	}
	c.writtenBytes[cluster.ClusterTrustBundleName] = append([]byte(nil), pemData...)

	c.updateCount++
	return nil
}

func expectedPEM(t *testing.T, bundle *types.Bundle) []byte {
	var out []byte
	for _, authority := range bundle.X509Authorities {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Asn1})...)
	}
	require.NotEmpty(t, out)
	return out
}

func getTestBundle(t *testing.T) *types.Bundle {
	cert, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
}
