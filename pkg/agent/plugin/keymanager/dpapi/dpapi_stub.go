//go:build !windows

package dpapi

import (
	"context"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func BuiltIn() catalog.BuiltIn {
	return catalog.MakeBuiltIn("dpapi",
		keymanagerv1.KeyManagerPluginServer(&unsupportedKeyManager{}),
		configv1.ConfigServiceServer(&unsupportedKeyManager{}))
}

type unsupportedKeyManager struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnimplementedConfigServer
}

func (*unsupportedKeyManager) Configure(_ context.Context, _ *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "the cng_dpapi key manager is only supported on Windows")
}

func (*unsupportedKeyManager) GenerateKey(_ context.Context, _ *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "the cng_dpapi key manager is only supported on Windows")
}

func (*unsupportedKeyManager) GetPublicKey(_ context.Context, _ *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "the cng_dpapi key manager is only supported on Windows")
}

func (*unsupportedKeyManager) GetPublicKeys(_ context.Context, _ *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "the cng_dpapi key manager is only supported on Windows")
}

func (*unsupportedKeyManager) SignData(_ context.Context, _ *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "the cng_dpapi key manager is only supported on Windows")
}
