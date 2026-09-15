package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDrainRunsTargetsConcurrently(t *testing.T) {
	const n = 5
	start := make(chan struct{})
	var entered sync.WaitGroup
	entered.Add(n)

	targets := make([]Target, 0, n)
	for i := 0; i < n; i++ {
		targets = append(targets, Target{
			Name: "target",
			Shutdown: func(ctx context.Context) error {
				entered.Done()
				<-start // every target must be running before any proceeds
				return nil
			},
		})
	}

	entryDone := make(chan struct{})
	go func() {
		entered.Wait()
		close(entryDone)
	}()

	go func() {
		select {
		case <-entryDone:
		case <-time.After(testTimeout):
		}
		close(start)
	}()

	Drain(context.Background(), nil, targets...)

	select {
	case <-entryDone:
	default:
		t.Fatal("Drain did not run every target concurrently")
	}
}

func TestDrainReportsEachTargetOnce(t *testing.T) {
	failure := errors.New("shutdown failed")
	targets := []Target{
		{Name: "a", Shutdown: func(context.Context) error { return nil }},
		{Name: "b", Shutdown: func(context.Context) error { return failure }},
	}

	var mu sync.Mutex
	results := map[string]error{}
	calls := map[string]int{}

	Drain(context.Background(), func(target Target, err error) {
		mu.Lock()
		defer mu.Unlock()
		results[target.Name] = err
		calls[target.Name]++
	}, targets...)

	if len(calls) != 2 || calls["a"] != 1 || calls["b"] != 1 {
		t.Fatalf("report call counts = %v, want exactly one call per target", calls)
	}
	if results["a"] != nil {
		t.Fatalf("target a error = %v, want nil", results["a"])
	}
	if !errors.Is(results["b"], failure) {
		t.Fatalf("target b error = %v, want %v", results["b"], failure)
	}
}

func TestDrainWaitsForAllTargetsDespiteOneHanging(t *testing.T) {
	var slowReturned, fastReturned bool
	var mu sync.Mutex

	targets := []Target{
		{
			Name: "slow",
			Shutdown: func(ctx context.Context) error {
				time.Sleep(50 * time.Millisecond)
				mu.Lock()
				slowReturned = true
				mu.Unlock()
				return nil
			},
		},
		{
			Name: "fast",
			Shutdown: func(ctx context.Context) error {
				mu.Lock()
				fastReturned = true
				mu.Unlock()
				return nil
			},
		},
	}

	Drain(context.Background(), nil, targets...)

	mu.Lock()
	defer mu.Unlock()
	if !slowReturned || !fastReturned {
		t.Fatalf("Drain returned before all targets finished: slow=%v fast=%v", slowReturned, fastReturned)
	}
}

func TestDrainNoTargetsReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		Drain(context.Background(), nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Drain with no targets did not return")
	}
}

func TestDrainPassesContextToTargets(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "value")

	var got any
	Drain(ctx, nil, Target{
		Name: "only",
		Shutdown: func(shutdownCtx context.Context) error {
			got = shutdownCtx.Value(ctxKey{})
			return nil
		},
	})

	if got != "value" {
		t.Fatalf("target did not receive the caller's context: got %v", got)
	}
}
