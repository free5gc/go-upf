package ees

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeNRF mimics the free5GC NRF: NFRegister is open, NFUpdate/NFDeregister
// need a Bearer token once OAuth2 is on.
type fakeNRF struct {
	mu        sync.Mutex
	calls     []string
	profile   map[string]any
	forget    bool // answer the next heartbeat with 404
	tokenForm map[string]string
}

func (f *fakeNRF) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		authorized := r.Header.Get("Authorization") == "Bearer tok-1"
		switch {
		case r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost:
			require.NoError(t, r.ParseForm())
			f.tokenForm = map[string]string{}
			for k := range r.PostForm {
				f.tokenForm[k] = r.PostForm.Get(k)
			}
			f.calls = append(f.calls, "TOKEN")
			w.Header().Set("Content-Type", "application/json")
			if _, err := io.WriteString(w, `{"access_token":"tok-1","token_type":"Bearer","expires_in":1000}`); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, nrfNFMPath) && r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(body, &f.profile))
			f.calls = append(f.calls, "PUT")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if _, err := io.WriteString(w, `{"heartBeatTimer":1}`); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, nrfNFMPath) && (r.Method == http.MethodPatch || r.Method == http.MethodDelete):
			if !authorized {
				f.calls = append(f.calls, r.Method+"-401")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodPatch {
				require.Equal(t, "application/json-patch+json", r.Header.Get("Content-Type"))
				if f.forget {
					f.forget = false
					f.calls = append(f.calls, "PATCH-404")
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}
			f.calls = append(f.calls, r.Method)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (f *fakeNRF) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func TestNRFRegistrarLifecycle(t *testing.T) {
	nrf := &fakeNRF{forget: false}
	srv := httptest.NewServer(nrf.handler(t))
	defer srv.Close()

	r, err := NewNRFRegistrar(srv.URL, "192.168.56.114", 8088, testLogger())
	require.NoError(t, err)
	require.Regexp(t, regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`),
		r.InstanceID())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Register, then the first heartbeat hits 401, gets a token and succeeds.
	require.Eventually(t, func() bool {
		calls := nrf.snapshot()
		return len(calls) >= 4 && calls[len(calls)-1] == "PATCH"
	}, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, []string{"PUT", "PATCH-401", "TOKEN", "PATCH"}, nrf.snapshot()[:4])

	nrf.mu.Lock()
	require.Equal(t, map[string]string{
		"grant_type": "client_credentials", "nfInstanceId": r.InstanceID(),
		"nfType": "UPF", "targetNfType": "NRF", "scope": "nnrf-nfm",
	}, nrf.tokenForm)
	profile := nrf.profile
	require.Equal(t, "UPF", profile["nfType"])
	require.Equal(t, r.InstanceID(), profile["nfInstanceId"])
	service := profile["nfServices"].([]any)[0].(map[string]any)
	require.Equal(t, "nupf-ee", service["serviceName"])
	endpoint := service["ipEndPoints"].([]any)[0].(map[string]any)
	require.Equal(t, "192.168.56.114", endpoint["ipv4Address"])
	require.EqualValues(t, 8088, endpoint["port"])
	nrf.forget = true // e.g. the NRF restarted and lost the profile
	nrf.mu.Unlock()

	require.Eventually(t, func() bool {
		calls := nrf.snapshot()
		for i, c := range calls {
			if c == "PATCH-404" && i+1 < len(calls) && calls[i+1] == "PUT" {
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "a forgotten profile is registered again")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("registrar did not stop")
	}
	calls := nrf.snapshot()
	require.Equal(t, "DELETE", calls[len(calls)-1], "deregisters on shutdown with the cached token")
}

func TestNRFRegistrarRetriesUntilNRFIsUp(t *testing.T) {
	nrf := &fakeNRF{}
	var up sync.Once
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ready:
			nrf.handler(t).ServeHTTP(w, r)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	r, err := NewNRFRegistrar(srv.URL+"/", "10.0.0.1", 9090, testLogger())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	time.Sleep(300 * time.Millisecond)
	require.Empty(t, nrf.snapshot())
	up.Do(func() { close(ready) })
	require.Eventually(t, func() bool { return len(nrf.snapshot()) > 0 }, 5*time.Second, 20*time.Millisecond)
	cancel()
	<-done
}

func TestNRFRegistrarRejectsBadConfig(t *testing.T) {
	for name, tc := range map[string]struct{ uri, ip string }{
		"relative uri":      {"127.0.0.10:8000", "10.0.0.1"},
		"with path":         {"http://127.0.0.10:8000/nnrf-nfm/v1", "10.0.0.1"},
		"ftp":               {"ftp://127.0.0.10", "10.0.0.1"},
		"unspecified ip":    {"http://127.0.0.10:8000", "0.0.0.0"},
		"empty ip":          {"http://127.0.0.10:8000", ""},
		"ipv6 not profiled": {"http://127.0.0.10:8000", "fd00::1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewNRFRegistrar(tc.uri, tc.ip, 8088, testLogger())
			require.Error(t, err)
		})
	}
}
