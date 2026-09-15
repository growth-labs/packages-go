package lifecycle

import (
	"os"
	"sync"
	"testing"
	"time"
)

const testTimeout = 2 * time.Second

func TestWaitForSignalReturnsFirstSignal(t *testing.T) {
	signals := make(chan os.Signal, 2)
	signals <- os.Interrupt

	received := WaitForSignal(signals, nil)
	if received != os.Interrupt {
		t.Fatalf("received = %v, want os.Interrupt", received)
	}
}

func TestWaitForSignalArmsForceExitOnSecondSignal(t *testing.T) {
	signals := make(chan os.Signal, 2)
	signals <- os.Interrupt

	var mu sync.Mutex
	var got os.Signal
	done := make(chan struct{})

	WaitForSignal(signals, func(s os.Signal) {
		mu.Lock()
		got = s
		mu.Unlock()
		close(done)
	})

	signals <- os.Kill

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("forceExit was not called within the timeout")
	}

	mu.Lock()
	defer mu.Unlock()
	if got != os.Kill {
		t.Fatalf("forceExit received = %v, want os.Kill", got)
	}
}

func TestWaitForSignalNilForceExitArmsNothing(t *testing.T) {
	signals := make(chan os.Signal, 2)
	signals <- os.Interrupt

	// Must not panic and must not block: nil forceExit arms no watcher.
	WaitForSignal(signals, nil)

	// A second signal with nobody watching just sits in the buffered
	// channel; proving that requires only that this test returns.
	signals <- os.Kill
}

func TestArmSecondSignalFiresOnTheNextSignalAfterArming(t *testing.T) {
	// ArmSecondSignal is documented to be called after the caller's own
	// select has already consumed the first delivered signal — simulate
	// that consumption here before arming, then prove the watcher fires on
	// the next signal delivered after it is armed, not before.
	signals := make(chan os.Signal, 2)
	signals <- os.Interrupt
	<-signals // caller's own select consuming the first signal

	fired := make(chan os.Signal, 1)
	ArmSecondSignal(signals, func(s os.Signal) { fired <- s })

	select {
	case s := <-fired:
		t.Fatalf("forceExit fired before any signal was delivered post-arming: %v", s)
	case <-time.After(100 * time.Millisecond):
		// Expected: nothing fired yet.
	}

	signals <- os.Kill
	select {
	case s := <-fired:
		if s != os.Kill {
			t.Fatalf("forceExit received = %v, want os.Kill", s)
		}
	case <-time.After(testTimeout):
		t.Fatal("forceExit was not called for the signal delivered after arming")
	}
}

func TestArmSecondSignalClosedChannelDoesNotPanic(t *testing.T) {
	signals := make(chan os.Signal)
	close(signals)

	called := make(chan struct{}, 1)
	ArmSecondSignal(signals, func(os.Signal) { called <- struct{}{} })

	select {
	case <-called:
		t.Fatal("forceExit must not be called for a closed channel's zero value")
	case <-time.After(100 * time.Millisecond):
	}
}
