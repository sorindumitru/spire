package cache

import (
	"context"
	"crypto"
	"crypto/x509"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	agentmetrics "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
)

// X509SVID holds onto the SVID certificate chain and private key.
type X509SVID struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

func (s X509SVID) ExpiresAt() time.Time {
	if len(s.Chain) == 0 {
		return time.Time{}
	}
	return s.Chain[0].NotAfter
}

// X509Identity holds the data for a single X509 workload identity.
type X509Identity struct {
	Entry      *common.RegistrationEntry
	SVID       []*x509.Certificate
	PrivateKey crypto.Signer
}

// UpdateSVIDs holds information for an X509 SVIDs update to the cache.
type UpdateSVIDs struct {
	// X509SVIDs is a set of updated X509-SVIDs that should be merged into
	// the cache, keyed by registration entry id.
	X509SVIDs map[string]*X509SVID
}

// X509WorkloadUpdate is used to convey X509 workload information to cache subscribers.
type X509WorkloadUpdate struct {
	Identities       []X509Identity
	Bundle           *spiffebundle.Bundle
	FederatedBundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (u *X509WorkloadUpdate) HasIdentity() bool {
	return len(u.Identities) > 0
}

const (
	// Default batch size for processing tainted SVIDs
	defaultProcessingBatchSize = 100
)

var (
	// Time interval between SVID batch processing
	processingTaintedX509SVIDInterval = 5 * time.Second
)

// X509LRUCache wraps LRUCache with X509-specific operations.
type X509LRUCache struct {
	*LRUCache[X509SVID, X509WorkloadUpdate]

	processingBatchSize     int
	taintedBatchProcessedCh chan struct{}
}

func NewX509LRUCache(config LRUCacheConfig[X509SVID, X509WorkloadUpdate]) *X509LRUCache {
	if config.BuildUpdate == nil {
		config.BuildUpdate = buildX509WorkloadUpdate
	}
	if config.ShouldPrefetch == nil {
		config.ShouldPrefetch = func(entry *common.RegistrationEntry) bool {
			return entry.GetAdditionalAttributes() == nil || !entry.AdditionalAttributes.DisableX509SvidPrefetch
		}
	}
	c := &X509LRUCache{
		processingBatchSize: defaultProcessingBatchSize,
	}
	c.LRUCache = NewLRUCache[X509SVID, X509WorkloadUpdate](config)
	return c
}

// CountX509SVIDs returns the number of cached X509 SVIDs (backward compat).
func (c *X509LRUCache) CountX509SVIDs() int {
	return c.CountSVIDs()
}

// UpdateSVIDs updates X509 SVIDs using the UpdateSVIDs struct (backward compat).
func (c *X509LRUCache) UpdateSVIDs(update *UpdateSVIDs) {
	c.LRUCache.UpdateSVIDs(update.X509SVIDs)
}

// Identities is only used by manager tests.
func (c *X509LRUCache) Identities() []X509Identity {
	c.LRUCache.mu.RLock()
	defer c.LRUCache.mu.RUnlock()

	out := make([]X509Identity, 0, len(c.LRUCache.records))
	for _, record := range c.LRUCache.records {
		svid, ok := c.LRUCache.svids[record.entry.EntryId]
		if !ok {
			continue
		}
		out = append(out, makeNewX509Identity(record, svid))
	}
	sortIdentities(out)
	return out
}

// FetchWorkloadUpdate builds a X509WorkloadUpdate for the given selectors.
func (c *X509LRUCache) FetchWorkloadUpdate(selectors []*common.Selector) *X509WorkloadUpdate {
	set, setDone := allocSelectorSet(selectors...)
	defer setDone()

	c.LRUCache.mu.RLock()
	defer c.LRUCache.mu.RUnlock()
	return buildX509WorkloadUpdate(c.LRUCache, set)
}

// TaintX509SVIDs initiates the processing of all cached SVIDs, checking if they are tainted
// by any of the provided authorities.
func (c *X509LRUCache) TaintX509SVIDs(ctx context.Context, taintedX509Authorities []*x509.Certificate) {
	c.LRUCache.mu.RLock()
	defer c.LRUCache.mu.RUnlock()

	var entriesToProcess []string
	for key, svid := range c.LRUCache.svids {
		if svid != nil && len(svid.Chain) > 0 {
			entriesToProcess = append(entriesToProcess, key)
		}
	}

	if len(entriesToProcess) == 0 {
		c.LRUCache.log.Debug("No SVID entries to process for tainted X.509 authorities")
		return
	}

	go func() {
		c.scheduleRotation(ctx, entriesToProcess, taintedX509Authorities)
	}()

	c.LRUCache.log.WithField(telemetry.Count, len(entriesToProcess)).
		Debug("Scheduled rotation for SVID entries due to tainted X.509 authorities")
}

func (c *X509LRUCache) scheduleRotation(ctx context.Context, entryIDs []string, taintedX509Authorities []*x509.Certificate) {
	ticker := c.LRUCache.clk.Ticker(processingTaintedX509SVIDInterval)
	defer ticker.Stop()

	if c.taintedBatchProcessedCh != nil {
		sort.Strings(entryIDs)
	}

	for {
		batchSize := min(c.processingBatchSize, len(entryIDs))
		processingEntries := entryIDs[:batchSize]

		c.processTaintedSVIDs(processingEntries, taintedX509Authorities)

		entryIDs = entryIDs[batchSize:]

		entriesLeftCount := len(entryIDs)
		if entriesLeftCount == 0 {
			c.LRUCache.log.Info("Finished processing all tainted entries")
			c.notifyTaintedBatchProcessed()
			return
		}
		c.LRUCache.log.WithField(telemetry.Count, entriesLeftCount).Info("There are tainted X.509 SVIDs left to be processed")
		c.notifyTaintedBatchProcessed()

		select {
		case <-ticker.C:
		case <-ctx.Done():
			c.LRUCache.log.WithError(ctx.Err()).Warn("Context cancelled, exiting rotation schedule")
			return
		}
	}
}

func (c *X509LRUCache) notifyTaintedBatchProcessed() {
	if c.taintedBatchProcessedCh != nil {
		c.taintedBatchProcessedCh <- struct{}{}
	}
}

func (c *X509LRUCache) processTaintedSVIDs(entryIDs []string, taintedX509Authorities []*x509.Certificate) {
	counter := telemetry.StartCall(c.LRUCache.metrics, telemetry.CacheManager, agentmetrics.CacheTypeWorkload, telemetry.ProcessTaintedX509SVIDs)
	defer counter.Done(nil)

	taintedSVIDs := 0

	c.LRUCache.mu.Lock()
	defer c.LRUCache.mu.Unlock()

	for _, entryID := range entryIDs {
		svid, exists := c.LRUCache.svids[entryID]
		if !exists || svid == nil {
			continue
		}

		isTainted, err := x509util.IsSignedByRoot(svid.Chain, taintedX509Authorities)
		if err != nil {
			c.LRUCache.log.WithError(err).
				WithField(telemetry.RegistrationID, entryID).
				Error("Failed to check if SVID is signed by tainted authority")
			continue
		}
		if isTainted {
			taintedSVIDs++
			delete(c.LRUCache.svids, entryID)
		}
	}

	agentmetrics.AddCacheManagerTaintedX509SVIDsSample(c.LRUCache.metrics, agentmetrics.CacheTypeWorkload, float32(taintedSVIDs))
	c.LRUCache.log.WithField(telemetry.TaintedX509SVIDs, taintedSVIDs).Info("Tainted X.509 SVIDs")
}

func buildX509WorkloadUpdate(cache *LRUCache[X509SVID, X509WorkloadUpdate], set selectorSet) *X509WorkloadUpdate {
	records, recordsDone := cache.getRecordsForSelectors(set)
	defer recordsDone()

	var identities []X509Identity
	if len(records) > 0 {
		identities = make([]X509Identity, 0, len(records))
		for record := range records {
			if svid, ok := cache.svids[record.entry.EntryId]; ok {
				identities = append(identities, makeNewX509Identity(record, svid))
			}
		}
		sortIdentities(identities)
		if len(identities) == 0 {
			identities = nil
		}
	}

	w := &X509WorkloadUpdate{
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
			} else {
				cache.log.WithFields(logrus.Fields{
					telemetry.RegistrationID:  identity.Entry.EntryId,
					telemetry.SPIFFEID:        identity.Entry.SpiffeId,
					telemetry.FederatedBundle: federatesWith,
				}).Warn("Federated bundle contents missing")
			}
		}
	}

	return w
}

func makeNewX509Identity(record *lruCacheRecord, svid *X509SVID) X509Identity {
	return X509Identity{
		Entry:      record.entry,
		SVID:       svid.Chain,
		PrivateKey: svid.PrivateKey,
	}
}
