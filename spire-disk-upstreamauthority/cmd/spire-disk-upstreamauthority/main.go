package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/clock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

// Configuratio defines the configuration for the plugin.
type Configuration struct {
	trustDomain spiffeid.TrustDomain

	CertFilePath string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath  string `hcl:"key_file_path" json:"key_file_path"`
}

// Plugin implements the UpstreamAuthority plugin
type Plugin struct {
	// UnimplementedUpstreamAuthorityServer is embedded to satisfy gRPC
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer
	// UnimplementedConfigServer is embedded to satisfy gRPC
	configv1.UnimplementedConfigServer

	certs      *caCerts
	upstreamCA *x509svid.UpstreamCA

	// test hooks
	clock clock.Clock

	// Configuration should be set atomically
	mtx    sync.RWMutex
	config *Configuration

	// The logger received from the framework via the SetLogger method
	logger hclog.Logger
}

type caCerts struct {
	certChain   []*x509.Certificate
	trustBundle []*x509.Certificate
}

// MintX509CAAndSubscribe implements the UpstreamAuthority MintX509CAAndSubscribe RPC. Mints an X.509 CA and responds
// with the signed X.509 CA certificate chain and upstream X.509 roots. If supported by the implementation, subsequent
// responses on the stream contain upstream X.509 root updates, otherwise the stream is closed after the initial response.
//
// Implementation note:
// The stream should be kept open in the face of transient errors
// encountered while tracking changes to the upstream X.509 roots as SPIRE
// Server will not reopen a closed stream until the next X.509 CA rotation.
func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()

	upstreamCA, upstreamCerts, err := p.reloadCA()
	if err != nil {
		return err
	}

	cert, err := upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to sign CSR: %v", err)
	}

	x509CAChain, err := x509certificate.ToPluginFromCertificates(append([]*x509.Certificate{cert}, upstreamCerts.certChain...))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates(upstreamCerts.trustBundle)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKeyAndSubscribe implements the UpstreamAuthority PublishJWTKeyAndSubscribe RPC. Publishes a JWT signing key
// upstream and responds with the upstream JWT keys. If supported by the implementation, subsequent responses on the
// stream contain upstream JWT key updates, otherwise the stream is closed after the initial response.
//
// This RPC is optional and will return NotImplemented if unsupported.
//
// Implementation note:
// The stream should be kept open in the face of transient errors
// encountered while tracking changes to the upstream JWT keys as SPIRE
// Server will not reopen a closed stream until the next JWT key rotation.
func (p *Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "not implemented")
}

func (p *Plugin) reloadCA() (*x509svid.UpstreamCA, *caCerts, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	upstreamCA, upstreamCerts, err := p.loadUpstreamCAAndCerts(p.config)
	switch {
	case err == nil:
		p.upstreamCA = upstreamCA
		p.certs = upstreamCerts
	case p.upstreamCA != nil:
		upstreamCA = p.upstreamCA
		upstreamCerts = p.certs
	default:
		return nil, nil, fmt.Errorf("no cached CA and failed to load CA: %w", err)
	}

	return upstreamCA, upstreamCerts, nil
}

// TODO: perhaps load this into the config
func (p *Plugin) loadUpstreamCAAndCerts(config *Configuration) (*x509svid.UpstreamCA, *caCerts, error) {
	key, err := pemutil.LoadPrivateKey(config.KeyFilePath)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA key: %v", err)
	}

	certs, err := pemutil.LoadCertificates(config.CertFilePath)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA cert: %v", err)
	}
	// pemutil guarantees at least 1 cert
	caCert := certs[0]
	if len(certs) != 1 {
		return nil, nil, status.Error(codes.InvalidArgument, "with no bundle_file_path configured only self-signed CAs are supported")
	}
	trustBundle := certs
	certs = nil

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(caCert, key)
	if err != nil {
		return nil, nil, err
	}
	if !matched {
		return nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate and private key do not match")
	}

	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()
	for _, c := range certs {
		intermediates.AddCert(c)
	}
	for _, c := range trustBundle {
		roots.AddCert(c)
	}
	selfVerifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}
	_, err = caCert.Verify(selfVerifyOpts)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate cannot be validated with the provided bundle or is not self-signed")
	}

	caCerts := &caCerts{
		certChain:   certs,
		trustBundle: trustBundle,
	}

	return x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, key),
		config.trustDomain,
		x509svid.UpstreamCAOptions{
			Clock: p.clock,
		},
	), caCerts, nil
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
// TODO: Remove if no configuration is required
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	upstreamCA, certs, err := p.loadUpstreamCAAndCerts(newConfig)
	if err != nil {
		return nil, err
	}

	// Set local vars from config struct
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = newConfig
	p.config.trustDomain = spiffeid.RequireTrustDomainFromString(req.CoreConfiguration.TrustDomain)
	p.certs = certs
	p.upstreamCA = upstreamCA

	return &configv1.ConfigureResponse{}, nil
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Configuration) {
	p.mtx.Lock()
	p.config = config
	p.mtx.Unlock()
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Configuration, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
