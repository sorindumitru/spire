package endpoints

import (
	"context"
	"sync"

	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mtx         sync.Mutex
	pidLimiters map[int]*rate.Limiter
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		pidLimiters: make(map[int]*rate.Limiter),
	}
}

func (r *RateLimiter) Preprocess(ctx context.Context, _ string, _ any) (context.Context, error) {

	pid := rpccontext.CallerPID(ctx)

	r.mtx.Lock()
	limiter, ok := r.pidLimiters[pid]
	if !ok {
		limiter = rate.NewLimiter(5, 1)
		r.pidLimiters[pid] = limiter
	}
	r.mtx.Unlock()

	err := limiter.Wait(ctx)
	return ctx, err
}

func (r *RateLimiter) Postprocess(ctx context.Context, _ string, _ bool, _ error) {
	// Nothing to do
}
