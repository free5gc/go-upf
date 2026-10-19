package forwarder

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenGtp5gInvalidAddress(t *testing.T) {
	var wg sync.WaitGroup
	// Address resolution fails before binding a UDP socket or creating a link.
	driver, err := OpenGtp5g(&wg, "127.0.0.1:65536", 1400)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("mux goroutine did not stop after startup failed")
	}

	require.Nil(t, driver)
	require.ErrorContains(t, err, "open link: resolve addr")
}
