package nodecache

import (
	"context"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	rebuildInterval = 5 * time.Second
)

type Cache struct {
	ds              datastore.DataStore
	buildTime       time.Time
	mtx             sync.RWMutex
	nodes           map[string]*common.AttestedNode
	nodeRefreshTime map[string]time.Time
}

func BuildFromDatastore(ctx context.Context, ds datastore.DataStore) (*Cache, error) {
	buildTime := time.Now()

	resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		ValidAt: buildTime,
	})
	if err != nil {
		return nil, err
	}

	cache := &Cache{
		ds:              ds,
		buildTime:       buildTime,
		nodes:           make(map[string]*common.AttestedNode),
		nodeRefreshTime: make(map[string]time.Time),
	}

	for _, node := range resp.Nodes {
		nodeID := node.SpiffeId
		cache.nodes[nodeID] = node
	}

	return cache, nil
}

func (c *Cache) FetchAttestedNode(id string) (*common.AttestedNode, time.Time, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	node, ok := c.nodes[id]
	if !ok {
		return nil, time.Time{}, nil
	}

	nodeRefreshTime, ok := c.nodeRefreshTime[id]
	if !ok {
		nodeRefreshTime = c.buildTime
	}

	return node, nodeRefreshTime, nil
}

func (c *Cache) RefreshAttestedNode(ctx context.Context, id string) (*common.AttestedNode, error) {
	node, err := c.ds.FetchAttestedNode(ctx, id)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.nodes[id] = node
	c.nodeRefreshTime[id] = time.Now()
	return node, nil
}

func (c *Cache) Rebuild(ctx context.Context) error {
	return nil
}

func (c *Cache) PeriodicRebuild(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.Tick(rebuildInterval):
		c.Rebuild(ctx)
	}

	return nil
}
