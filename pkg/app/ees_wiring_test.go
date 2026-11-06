package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/pkg/factory"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func listening(addr string) bool {
	conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return false
	}
	return conn.Close() == nil
}

// the "ees" block of the UPF YAML maps to ip/port; old keys are ignored.
func TestValidationEESConfigKeys(t *testing.T) {
	var cfg factory.Config
	require.NoError(t, yaml.Unmarshal([]byte(`
ees:
  enabled: true
  ip: 192.168.107.10
  port: 9090
  listenAddr: "10.0.0.1:1"
  periodSec: 5
`), &cfg))
	require.Equal(t, &factory.EESConfig{Enabled: true, IP: "192.168.107.10", Port: 9090}, cfg.EES)
}

// initEES starts nothing unless enabled, and serves the API when enabled.
func TestValidationInitEESWiring(t *testing.T) {
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for name, ees := range map[string]*factory.EESConfig{
		"absent":   nil,
		"disabled": {Enabled: false, IP: "127.0.0.1", Port: port},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &factory.Config{Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1"}, EES: ees}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u := &UpfApp{ctx: ctx, cfg: cfg, pfcpServer: pfcp.NewPfcpServer(cfg, forwarder.Empty{})}
			require.NoError(t, u.initEES())
			require.Nil(t, u.eesServer)
			time.Sleep(100 * time.Millisecond)
			require.False(t, listening(addr), "no EES listener when disabled")
			cancel()
			u.wg.Wait()
		})
	}

	t.Run("enabled", func(t *testing.T) {
		cfg := &factory.Config{
			Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1"},
			EES:  &factory.EESConfig{Enabled: true, IP: "127.0.0.1", Port: port},
		}
		ctx, cancel := context.WithCancel(context.Background())
		u := &UpfApp{ctx: ctx, cfg: cfg, pfcpServer: pfcp.NewPfcpServer(cfg, forwarder.Empty{})}
		require.NoError(t, u.initEES())
		require.NotNil(t, u.eesServer)
		require.Eventually(t, func() bool { return listening(addr) }, 2*time.Second, 20*time.Millisecond)

		body := []byte(`{"subscription":{"nfId":"n","eventNotifyUri":"http://127.0.0.1:1/n","notifyCorrelationId":"c",
"eventList":[{"type":"USER_DATA_USAGE_MEASURES","granularityOfMeasurement":"PER_SESSION",
"measurementTypes":["VOLUME_MEASUREMENT"]}],"eventReportingMode":{"trigger":"ONE_TIME"},"anyUe":true}}`)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://"+addr+"/nupf-ee/v1/ee-subscriptions", bytes.NewReader(body))
		require.NoError(t, err)
		rsp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, rsp.Body.Close())
		require.Equal(t, http.StatusCreated, rsp.StatusCode)

		// Same order as listenShutdownEvent: stop the API, then the routines.
		shutdownCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		require.NoError(t, u.eesServer.Shutdown(shutdownCtx))
		cancel()
		u.wg.Wait()
		require.False(t, listening(addr))
	})
}

// the UPF-owned URR and NRF settings live in the ees block.
func TestValidationUPFURRConfigKeys(t *testing.T) {
	var cfg factory.Config
	require.NoError(t, yaml.Unmarshal([]byte(`
ees:
  upfUrrEnabled: true
  upfUrrPeriod: 2
`), &cfg))
	require.Equal(t, &factory.EESConfig{UpfURREnabled: true, UpfURRPeriod: 2},
		cfg.EES)
}

// ees.enabled and ees.upfUrrEnabled are independent: either starts the API,
// each one reports its own URR, and neither starts nothing.
func TestValidationIndependentEESSwitches(t *testing.T) {
	for name, tc := range map[string]struct {
		smf     bool
		upf     bool
		running bool
	}{
		"both off":            {},
		"SMF URR 2 only":      {smf: true, running: true},
		"UPF-owned URR only":  {upf: true, running: true},
		"both on (both URRs)": {smf: true, upf: true, running: true},
	} {
		t.Run(name, func(t *testing.T) {
			port := freePort(t)
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			cfg := &factory.Config{
				Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1"},
				EES:  &factory.EESConfig{Enabled: tc.smf, UpfURREnabled: tc.upf, IP: "127.0.0.1", Port: port},
			}
			ctx, cancel := context.WithCancel(context.Background())
			u := &UpfApp{ctx: ctx, cfg: cfg, pfcpServer: pfcp.NewPfcpServer(cfg, forwarder.Empty{})}
			require.NoError(t, u.initEES())
			require.Equal(t, tc.running, u.eesServer != nil)
			require.Equal(t, tc.upf, u.pfcpServer.UPFOwnedURRsEnabled())
			if tc.running {
				require.Eventually(t, func() bool { return listening(addr) }, 2*time.Second, 20*time.Millisecond)
				shutdownCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
				defer done()
				require.NoError(t, u.eesServer.Shutdown(shutdownCtx))
			} else {
				time.Sleep(100 * time.Millisecond)
				require.False(t, listening(addr))
			}
			cancel()
			u.wg.Wait()
		})
	}
}

func TestValidationEESRejectsBadSettings(t *testing.T) {
	for name, settings := range map[string]factory.EESConfig{
		"negative period": {UpfURRPeriod: -1},
		"huge period":     {UpfURRPeriod: 86401},
	} {
		t.Run(name, func(t *testing.T) {
			settings.UpfURREnabled, settings.IP, settings.Port = true, "127.0.0.1", freePort(t)
			cfg := &factory.Config{
				Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1"},
				EES:  &settings,
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u := &UpfApp{ctx: ctx, cfg: cfg, pfcpServer: pfcp.NewPfcpServer(cfg, forwarder.Empty{})}
			require.Error(t, u.initEES())
			require.Nil(t, u.eesServer)
		})
	}
}
