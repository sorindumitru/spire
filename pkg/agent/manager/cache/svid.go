package cache

import "time"

// CachedSVID is the constraint for any SVID type storable in the generic LRU cache.
type CachedSVID interface {
	ExpiresAt() time.Time
}
