package dpapi

import (
	"context"
	"runtime"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/dpapi"
	keymanagertest "github.com/spiffe/spire/pkg/agent/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

func TestKeyManagerContract(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CNG DPAPI key manager is Windows-only")
	}
	keymanagertest.Test(t, keymanagertest.Config{
		Create: func(t *testing.T) keymanager.KeyManager {
			km, err := loadPlugin(t, "")
			if err != nil {
				t.Fatalf("failed to load plugin: %v", err)
			}
			return km
		},
	})
}

func TestConfigureNotSupportedOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test is for non-Windows platforms only")
	}
	_, err := loadPlugin(t, "")
	spiretest.RequireGRPCStatusContains(t, err, codes.FailedPrecondition, "only supported on Windows")
}

func TestGenerateKeyBeforeConfigure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("CNG DPAPI key manager is Windows-only")
	}
	km := new(keymanager.V1)
	plugintest.Load(t, cngdpapi.BuiltIn(), km)

	_, err := km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	spiretest.RequireGRPCStatusContains(t, err, codes.FailedPrecondition, "not configured")
}

func loadPlugin(t *testing.T, configFmt string, configArgs ...any) (keymanager.KeyManager, error) {
	km := new(keymanager.V1)
	var configErr error
	plugintest.Load(t, cngdpapi.BuiltIn(), km,
		plugintest.Configuref(configFmt, configArgs...),
		plugintest.CaptureConfigureError(&configErr),
	)
	return km, configErr
}
