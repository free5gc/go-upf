// Command ees-harness serves the real UPF EES handler for cross-repository
// contract tests. The SMF tests start it as a separate process because Go's
// internal-package rule prevents either repository importing the other.
//
// It prints one JSON line {"nupfApiRoot": ..., "control": ...} once both
// listeners accept connections, and exits on SIGINT/SIGTERM or stdin EOF.
//
// The control listener is test-only: POST /usage injects a measurement through
// Aggregator.PushReportWithContext (the same entry as PFCP/kernel reports) and
// GET /subscriptions returns how the UPF mapped each accepted subscription.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/report"
)

type usageRequest struct {
	UeIPv4     string `json:"ueIpv4"`
	LocalSEID  uint64 `json:"localSeid"`
	RemoteSEID uint64 `json:"remoteSeid"`
	Generation uint64 `json:"generation"`
	URRID      uint32 `json:"urrId"`
	ULBytes    uint64 `json:"ulBytes"`
	DLBytes    uint64 `json:"dlBytes"`
}

type subscriptionView struct {
	ID               string   `json:"id"`
	NfID             string   `json:"nfId"`
	NotifURI         string   `json:"notifUri"`
	CorrelationID    string   `json:"correlationId"`
	Mode             string   `json:"mode"`
	PeriodSec        int      `json:"periodSec"`
	UeIPv4           string   `json:"ueIpv4"`
	AnyUE            bool     `json:"anyUe"`
	MeasurementTypes []string `json:"measurementTypes"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	log := logrus.New()
	log.SetOutput(os.Stderr)
	logger := logrus.NewEntry(log).WithField("component", "ees-harness")

	store := ees.NewSubscriptionStore("")
	aggregator := ees.NewAggregator(store, 0, ees.NewNotifier(logger), logger, nil, nil)
	server := ees.NewServer(store, aggregator, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			logger.WithError(err).Debug("stdin read failed")
		}
		stop()
	}()

	aggregatorDone := make(chan struct{})
	go func() {
		aggregator.Run(ctx)
		close(aggregatorDone)
	}()

	// Serve() owns the production listener and protocol setup, so give it a
	// concrete address instead of wrapping Handler() in a test server.
	nupfAddr, err := freeLoopbackAddr()
	if err != nil {
		return err
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(nupfAddr) }()

	control, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	controlServer := &http.Server{
		Handler: controlHandler(store, aggregator, logger), ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if serveErr := controlServer.Serve(control); !errors.Is(serveErr, http.ErrServerClosed) {
			logger.WithError(serveErr).Error("control server stopped")
		}
	}()

	if err := waitForListener(ctx, nupfAddr, serveErr); err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"nupfApiRoot": "http://" + nupfAddr,
		"control":     "http://" + control.Addr().String(),
	}); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := controlServer.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Warn("control server shutdown")
	}
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Warn("ees server shutdown")
	}
	<-aggregatorDone
	return nil
}

func controlHandler(store *ees.SubscriptionStore, aggregator *ees.Aggregator, logger *logrus.Entry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /usage", func(w http.ResponseWriter, r *http.Request) {
		var req usageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.URRID == 0 {
			req.URRID = ees.SingleUPFMAQEURRID
		}
		end := time.Now()
		aggregator.PushReportWithContext(report.SessReport{SEID: req.LocalSEID, Reports: []report.Report{
			report.USAReport{
				URRID: req.URRID, StartTime: end.Add(-time.Second), EndTime: end,
				VolumMeasure: report.VolumeMeasure{UplinkVolume: req.ULBytes, DownlinkVolume: req.DLBytes},
			},
		}}, ees.SessionContext{RemoteSEID: req.RemoteSEID, Generation: req.Generation, UeIPv4Addr: req.UeIPv4})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /subscriptions", func(w http.ResponseWriter, _ *http.Request) {
		views := []subscriptionView{}
		for _, sub := range store.AllSubscriptions() {
			view := subscriptionView{
				ID: sub.ID, NfID: sub.NfID, NotifURI: sub.NotifURI, CorrelationID: sub.NotifyCorrelationID,
				Mode: string(sub.Mode), PeriodSec: sub.PeriodSec,
				UeIPv4: sub.Target.UeIPAddress, AnyUE: sub.Target.AnyUE,
			}
			for _, mt := range sub.MeasurementTypes {
				view.MeasurementTypes = append(view.MeasurementTypes, string(mt))
			}
			views = append(views, view)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(views); err != nil {
			logger.WithError(err).Warn("encode subscriptions")
		}
	})
	return mux
}

func freeLoopbackAddr() (string, error) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := listener.Addr().String()
	return addr, listener.Close()
}

func waitForListener(ctx context.Context, addr string, serveErr <-chan error) error {
	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serveErr:
			return fmt.Errorf("ees server exited before ready: %v", err)
		default:
		}
		if conn, err := dialer.DialContext(ctx, "tcp", addr); err == nil {
			return conn.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("ees server did not listen on %s", addr)
}
