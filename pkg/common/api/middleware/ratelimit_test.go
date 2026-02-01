package middleware

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
)

func TestRateLimiting(t *testing.T) {
	limiters := NewFakeLimiters()

	m := NewGarbageCollectedLimiter[string](10)

	// Once exceeding burst size for A
	err := m.RateLimit(t.Context(), "A", 11)
	spiretest.RequireGRPCStatus(t, err, codes.ResourceExhausted, "rate (11) exceeds burst size (10)")

	// Once within burst size for A
	require.NoError(t, m.RateLimit(t.Context(), "A", 1))

	// Twice within burst size for B
	require.NoError(t, m.RateLimit(t.Context(), "B", 2))
	require.NoError(t, m.RateLimit(t.Context(), "B", 3))

	// There should be two rate limiters; A, and B
	assert.Equal(t, 2, limiters.Count)

	// WaitN should have only been called once for A (burst failure does
	// not result in a call to WaitN) and twice for B.
	assert.Equal(t, []WaitNEvent{
		{ID: 1, Count: 1},
		{ID: 2, Count: 2},
		{ID: 2, Count: 3},
	}, limiters.WaitNEvents)
}

func TestRateLimiterIsGarbageCollected(t *testing.T) {
	mockClk, restoreClk := setupLimiterClock(t)
	defer restoreClk()

	limiters := NewFakeLimiters()

	l := NewGarbageCollectedLimiter[string](2)

	// Create limiters for both "A" and "B"
	require.NoError(t, l.RateLimit(t.Context(), "A", 1))
	require.NoError(t, l.RateLimit(t.Context(), "B", 1))
	require.Equal(t, 2, limiters.Count)

	// Advance past the GC time and create for limiter for "C". This should
	// move both "A" and "B" into the "previous" set. There should be
	// three total limiters now.
	mockClk.Add(gcInterval)
	require.NoError(t, l.RateLimit(t.Context(), "C", 1))
	require.Equal(t, 3, limiters.Count)

	// Now use the "A" limiter. This should transition it into the
	// "current" set. Assert that no new limiter is created.
	require.NoError(t, l.RateLimit(t.Context(), "A", 1))
	require.Equal(t, 3, limiters.Count)

	// Advance to the next GC time. Create a limiter for "D". This should
	// cause "B" to be removed. "A" and "C" will go into the
	// "previous set".
	mockClk.Add(gcInterval)
	require.NoError(t, l.RateLimit(t.Context(), "D", 1))
	require.Equal(t, 4, limiters.Count)

	// Use all the limiters but "B" and make sure the limiter count is stable.
	require.NoError(t, l.RateLimit(t.Context(), "A", 1))
	require.NoError(t, l.RateLimit(t.Context(), "C", 1))
	require.NoError(t, l.RateLimit(t.Context(), "D", 1))
	require.Equal(t, 4, limiters.Count)

	slog.Info("Limiter", "current", l.current, "previous", l.previous)

	// Now do "B". A new limiter will be created for "B", since the
	// limiter for "B" was previously removed after the last GC period.
	require.NoError(t, l.RateLimit(t.Context(), "B", 1))
	require.Equal(t, 5, limiters.Count)
}

type WaitNEvent struct {
	ID    int
	Count int
}

type FakeLimiters struct {
	Count       int
	WaitNEvents []WaitNEvent
}

func NewFakeLimiters() *FakeLimiters {
	ls := &FakeLimiters{}
	newRawRateLimiter = ls.newRawRateLimiter
	return ls
}

func (ls *FakeLimiters) newRawRateLimiter(limit rate.Limit, burst int) rawRateLimiter {
	ls.Count++
	return &fakeLimiter{
		id:    ls.Count,
		waitN: ls.waitN,
		limit: limit,
		burst: burst,
	}
}

func (ls *FakeLimiters) waitN(_ context.Context, id, count int) error {
	ls.WaitNEvents = append(ls.WaitNEvents, WaitNEvent{
		ID:    id,
		Count: count,
	})
	return nil
}

type fakeLimiter struct {
	id    int
	waitN func(ctx context.Context, id, count int) error
	limit rate.Limit
	burst int
}

func (l *fakeLimiter) WaitN(ctx context.Context, count int) error {
	switch {
	case l.limit == rate.Inf:
		// Limiters should never be unlimited.
		return errors.New("unexpected infinite limit on limiter")
	case count > l.burst:
		// the waitN() function should have already taken care of this check
		// in order to provide nicer error messaging than that provided by
		// the rate package.
		return errors.New("exceeding burst should have already been handled")
	}
	return l.waitN(ctx, l.id, count)
}

func (l *fakeLimiter) Limit() rate.Limit {
	return l.limit
}

func (l *fakeLimiter) Burst() int {
	return l.burst
}

func setupLimiterClock(t *testing.T) (*clock.Mock, func()) {
	mockClk := clock.NewMock(t)
	oldClk := clk
	clk = mockClk
	return mockClk, func() {
		clk = oldClk
	}
}
