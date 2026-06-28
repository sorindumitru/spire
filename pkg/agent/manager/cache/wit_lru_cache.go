package cache

import (
	"crypto"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
)

// WITSVID holds onto the WIT-SVID token and private key.
type WITSVID struct {
	Token      string
	PrivateKey crypto.Signer
	ExpiresOn  time.Time
}

func (s WITSVID) ExpiresAt() time.Time {
	return s.ExpiresOn
}

// WITIdentity holds the data for a single WIT-SVID workload identity.
type WITIdentity struct {
	Entry      *common.RegistrationEntry
	Token      string
	PrivateKey crypto.Signer
}

// WITWorkloadUpdate is used to convey WIT workload information to cache subscribers.
type WITWorkloadUpdate struct {
	Identities       []WITIdentity
	Bundle           *spiffebundle.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (u *WITWorkloadUpdate) HasIdentity() bool {
	return len(u.Identities) > 0
}

// WITLRUCache wraps LRUCache with WIT-SVID-specific operations.
type WITLRUCache struct {
	*LRUCache[WITSVID, WITWorkloadUpdate]
}

func NewWITLRUCache(config LRUCacheConfig[WITSVID, WITWorkloadUpdate]) *WITLRUCache {
	if config.BuildUpdate == nil {
		config.BuildUpdate = buildWITWorkloadUpdate
	}
	c := &WITLRUCache{}
	c.LRUCache = NewLRUCache[WITSVID, WITWorkloadUpdate](config)
	return c
}

func buildWITWorkloadUpdate(cache *LRUCache[WITSVID, WITWorkloadUpdate], set selectorSet) *WITWorkloadUpdate {
	records, recordsDone := cache.getRecordsForSelectors(set)
	defer recordsDone()

	identities := make([]WITIdentity, 0, len(records))
	for record := range records {
		if svid, ok := cache.svids[record.entry.EntryId]; ok {
			identities = append(identities, WITIdentity{
				Entry:      record.entry,
				Token:      svid.Token,
				PrivateKey: svid.PrivateKey,
			})
		}
	}

	w := &WITWorkloadUpdate{
		Bundle:           cache.bundles[cache.trustDomain],
		FederatedBundles: make(map[spiffeid.TrustDomain]*spiffebundle.Bundle),
		Identities:       identities,
	}

	for _, identity := range w.Identities {
		for _, federatesWith := range identity.Entry.FederatesWith {
			td, err := spiffeid.TrustDomainFromString(federatesWith)
			if err != nil {
				cache.log.WithFields(logrus.Fields{
					telemetry.TrustDomainID: federatesWith,
					logrus.ErrorKey:         err,
				}).Warn("Invalid federated trust domain")
				continue
			}
			if federatedBundle := cache.bundles[td]; federatedBundle != nil {
				w.FederatedBundles[td] = federatedBundle
			}
		}
	}

	return w
}
