package cache

import (
	"testing"
	"time"

	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	clk := clock.NewMock(t)
	cache := NewCache[string, string](clk)

	_, ok := cache.Get("hello")
	require.False(t, ok)

	setValue := "world"
	cache.Set("hello", &setValue, clk.Now().Add(time.Minute))
	value, ok := cache.Get("hello")
	require.True(t, ok)
	require.Equal(t, &setValue, value)

	clk.Add(time.Minute + time.Second)
	_, ok = cache.Get("hello")
	require.False(t, ok)
}

func TestCacheDeletion(t *testing.T) {
	clk := clock.NewMock(t)
	cache := NewCache[string, string](clk)

	// Deleting a non-existing key should work
	cache.Delete("hello")

	_, ok := cache.Get("hello")
	require.False(t, ok)

	setValue := "world"
	cache.Set("hello", &setValue, clk.Now().Add(time.Minute))
	value, ok := cache.Get("hello")
	require.True(t, ok)
	require.Equal(t, &setValue, value)

	cache.Delete("hello")

	_, ok = cache.Get("hello")
	require.False(t, ok)
}
