package middleware

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	gcInterval = time.Minute
)

var (
	// Used to manipulate time in unit tests
	clk = clock.New()

	// newRawRateLimiter is used to create a new ratelimiter. It returns a limiter
	// from the standard rate package by default production.
	newRawRateLimiter = func(limit rate.Limit, burst int) rawRateLimiter {
		return rate.NewLimiter(limit, burst)
	}
)

type rawRateLimiter interface {
	WaitN(ctx context.Context, count int) error
	Limit() rate.Limit
	Burst() int
}

type GarbageCollectedLimiter[Key comparable] struct {
	limit  int
	lastGC time.Time

	mtx sync.RWMutex

	current  map[Key]rawRateLimiter
	previous map[Key]rawRateLimiter
}

func NewGarbageCollectedLimiter[Key comparable](limit int) *GarbageCollectedLimiter[Key] {
	return &GarbageCollectedLimiter[Key]{
		limit:   limit,
		current: make(map[Key]rawRateLimiter),
		lastGC:  clk.Now(),
	}
}

func (lim *GarbageCollectedLimiter[Key]) RateLimit(ctx context.Context, key Key, count int) error {
	limiter := lim.getLimiter(key)
	return waitN(ctx, limiter, count)
}

func (lim *GarbageCollectedLimiter[Key]) getLimiter(key Key) rawRateLimiter {
	lim.mtx.RLock()
	limiter, ok := lim.current[key]
	if ok {
		lim.mtx.RUnlock()
		return limiter
	}
	lim.mtx.RUnlock()

	// A limiter does not exist for the given key
	lim.mtx.Lock()
	defer lim.mtx.Unlock()

	// Check the "current" entries in case another goroutine raced on this IP.
	if limiter, ok = lim.current[key]; ok {
		return limiter
	}

	// Then check the "previous" entries to see if a limiter exists for this
	// key as of the last GC. If so, move it to current and return it.
	if limiter, ok = lim.previous[key]; ok {
		lim.current[key] = limiter
		delete(lim.previous, key)
		return limiter
	}

	// There is no limiter for this key. Before we create one, we should see
	// if we need to do GC.
	now := clk.Now()
	if now.Sub(lim.lastGC) >= gcInterval {
		lim.previous = lim.current
		lim.current = make(map[Key]rawRateLimiter)
		lim.lastGC = now
	}

	limiter = newRawRateLimiter(rate.Limit(lim.limit), lim.limit)
	lim.current[key] = limiter
	return limiter
}

func waitN(ctx context.Context, limiter rawRateLimiter, count int) (err error) {
	// limiter.WaitN already provides this check but the error returned is not
	// strongly typed and is a little messy. Lifting this check so we can
	// provide a clean error message.
	if count > limiter.Burst() && limiter.Limit() != rate.Inf {
		return status.Errorf(codes.ResourceExhausted, "rate (%d) exceeds burst size (%d)", count, limiter.Burst())
	}

	err = limiter.WaitN(ctx, count)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ctx.Err()
	default:
		return status.Error(codes.ResourceExhausted, err.Error())
	}
}
