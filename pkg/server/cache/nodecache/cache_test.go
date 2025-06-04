package nodecache

import (
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestBuildCache(t *testing.T) {
	ds := fakedatastore.New(t)

	firstAgent := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/agent-1",
		AttestationDataType: "example",
		CertSerialNumber:    "123456",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}
	secondAgent := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/agent-2",
		AttestationDataType: "example",
		CertSerialNumber:    "234567",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}
	expiredAgent := &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/agent-expired",
		AttestationDataType: "example",
		CertSerialNumber:    "345678",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}
	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), secondAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), expiredAgent)
	require.NoError(t, err)

	cache, err := BuildFromDatastore(t.Context(), ds)
	require.NoError(t, err)

	cachedFirstAgent, firstAgentTime, err := cache.FetchAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedFirstAgent, firstAgent)

	cachedSecondAgent, secondAgentTime, err := cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedSecondAgent, secondAgent)
	require.Equal(t, firstAgentTime, secondAgentTime)

	cachedExpiredAgent, _, err := cache.FetchAttestedNode(expiredAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedExpiredAgent)

	secondAgent.CertSerialNumber = "456789"
	_, err = ds.UpdateAttestedNode(t.Context(), secondAgent, nil)
	require.NoError(t, err)

	refreshedSecondAgent, err := cache.RefreshAttestedNode(t.Context(), secondAgent.SpiffeId)
	require.NoError(t, err)

	cachedSecondAgent, secondAgentTimeAfterRefresh, err := cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, refreshedSecondAgent, secondAgent)
	require.Greater(t, secondAgentTimeAfterRefresh, secondAgentTime)
}
