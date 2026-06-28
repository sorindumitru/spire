package manager

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBundle(td spiffeid.TrustDomain) *spiffebundle.Bundle {
	return spiffebundle.FromX509Authorities(td, []*x509.Certificate{{Raw: []byte{1}}})
}

func TestUpdateWITSVIDs(t *testing.T) {
	clk := clock.NewMock(t)
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	bundle := testBundle(td)

	witCache := cache.NewWITLRUCache(cache.LRUCacheConfig[cache.WITSVID, cache.WITWorkloadUpdate]{
		Log:         testLogger,
		TrustDomain: td,
		Bundle:      bundle,
		Metrics:     &telemetry.Blackhole{},
		Clk:         clk,
	})

	entry := &common.RegistrationEntry{
		EntryId:   "entry-1",
		ParentId:  "spiffe://domain.test/node",
		SpiffeId:  "spiffe://domain.test/workload-1",
		Selectors: []*common.Selector{{Type: "unix", Value: "uid:1000"}},
	}

	witCache.UpdateEntries(&cache.UpdateEntries{
		Bundles:             map[spiffeid.TrustDomain]*cache.Bundle{td: bundle},
		RegistrationEntries: map[string]*common.RegistrationEntry{"entry-1": entry},
	}, nil)

	// Create a subscriber so the entry becomes stale
	sub := witCache.NewSubscriber([]*common.Selector{{Type: "unix", Value: "uid:1000"}})
	defer sub.Finish()
	witCache.SyncSVIDsWithSubscribers()

	require.Len(t, witCache.GetStaleEntries(), 1)

	fakeClient := &fakeWITClient{
		witSVIDs: map[string]*client.WITSVID{
			"entry-1": {
				Token:     "test-token-1",
				IssuedAt:  clk.Now(),
				ExpiresAt: clk.Now().Add(time.Hour),
			},
		},
	}

	m := &manager{
		c: &Config{
			Log:              testLogger,
			TrustDomain:      td,
			Metrics:          &telemetry.Blackhole{},
			Clk:              clk,
			WorkloadKeyType:  workloadkey.ECP256,
			RotationStrategy: rotationutil.NewRotationStrategy(0),
		},
		witCache: witCache,
		client:   fakeClient,
	}

	err := m.updateWITSVIDs(context.Background())
	require.NoError(t, err)

	// Verify the client was called with a public key for the entry
	require.Len(t, fakeClient.lastPublicKeys, 1)
	assert.Contains(t, fakeClient.lastPublicKeys, "entry-1")

	// Verify the cache no longer has stale entries
	assert.Empty(t, witCache.GetStaleEntries())

	// Verify the SVID is now cached (subscriber should get an update)
	assert.Equal(t, 1, witCache.CountSVIDs())
}

func TestUpdateWITSVIDsNoStaleEntries(t *testing.T) {
	clk := clock.NewMock(t)
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	bundle := testBundle(td)

	witCache := cache.NewWITLRUCache(cache.LRUCacheConfig[cache.WITSVID, cache.WITWorkloadUpdate]{
		Log:         testLogger,
		TrustDomain: td,
		Bundle:      bundle,
		Metrics:     &telemetry.Blackhole{},
		Clk:         clk,
	})

	fakeClient := &fakeWITClient{}

	m := &manager{
		c: &Config{
			Log:              testLogger,
			TrustDomain:      td,
			Metrics:          &telemetry.Blackhole{},
			Clk:              clk,
			WorkloadKeyType:  workloadkey.ECP256,
			RotationStrategy: rotationutil.NewRotationStrategy(0),
		},
		witCache: witCache,
		client:   fakeClient,
	}

	err := m.updateWITSVIDs(context.Background())
	require.NoError(t, err)

	// Client should not have been called
	assert.Nil(t, fakeClient.lastPublicKeys)
}

func TestUpdateWITSVIDsClientError(t *testing.T) {
	clk := clock.NewMock(t)
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	bundle := testBundle(td)

	witCache := cache.NewWITLRUCache(cache.LRUCacheConfig[cache.WITSVID, cache.WITWorkloadUpdate]{
		Log:         testLogger,
		TrustDomain: td,
		Bundle:      bundle,
		Metrics:     &telemetry.Blackhole{},
		Clk:         clk,
	})

	entry := &common.RegistrationEntry{
		EntryId:   "entry-1",
		ParentId:  "spiffe://domain.test/node",
		SpiffeId:  "spiffe://domain.test/workload-1",
		Selectors: []*common.Selector{{Type: "unix", Value: "uid:1000"}},
	}

	witCache.UpdateEntries(&cache.UpdateEntries{
		Bundles:             map[spiffeid.TrustDomain]*cache.Bundle{td: bundle},
		RegistrationEntries: map[string]*common.RegistrationEntry{"entry-1": entry},
	}, nil)

	sub := witCache.NewSubscriber([]*common.Selector{{Type: "unix", Value: "uid:1000"}})
	defer sub.Finish()
	witCache.SyncSVIDsWithSubscribers()

	fakeClient := &fakeWITClient{
		err: errors.New("server unavailable"),
	}

	m := &manager{
		c: &Config{
			Log:              testLogger,
			TrustDomain:      td,
			Metrics:          &telemetry.Blackhole{},
			Clk:              clk,
			WorkloadKeyType:  workloadkey.ECP256,
			RotationStrategy: rotationutil.NewRotationStrategy(0),
		},
		witCache: witCache,
		client:   fakeClient,
	}

	err := m.updateWITSVIDs(context.Background())
	require.ErrorContains(t, err, "server unavailable")

	// Entry should still be stale
	assert.Len(t, witCache.GetStaleEntries(), 1)
}

func TestSyncSVIDsNilWITCache(t *testing.T) {
	clk := clock.NewMock(t)
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	bundle := testBundle(td)

	x509Cache := cache.NewX509LRUCache(cache.LRUCacheConfig[cache.X509SVID, cache.X509WorkloadUpdate]{
		Log:         testLogger,
		TrustDomain: td,
		Bundle:      bundle,
		Metrics:     &telemetry.Blackhole{},
		Clk:         clk,
	})

	m := &manager{
		c: &Config{
			Log:              testLogger,
			TrustDomain:      td,
			Metrics:          &telemetry.Blackhole{},
			Clk:              clk,
			WorkloadKeyType:  workloadkey.ECP256,
			RotationStrategy: rotationutil.NewRotationStrategy(0),
		},
		cache:    x509Cache,
		witCache: nil,
		client:   &fakeWITClient{},
	}

	// Should not panic with nil witCache
	err := m.syncSVIDs(context.Background())
	require.NoError(t, err)
}

type fakeWITClient struct {
	client.Client
	witSVIDs       map[string]*client.WITSVID
	err            error
	lastPublicKeys map[string]crypto.PublicKey
}

func (f *fakeWITClient) NewWITSVIDs(_ context.Context, publicKeys map[string]crypto.PublicKey) (map[string]*client.WITSVID, error) {
	f.lastPublicKeys = publicKeys
	if f.err != nil {
		return nil, f.err
	}
	return f.witSVIDs, nil
}

func (f *fakeWITClient) NewX509SVIDs(_ context.Context, _ map[string][]byte) (map[string]*client.X509SVID, error) {
	return nil, nil
}

func (f *fakeWITClient) Release() {}
