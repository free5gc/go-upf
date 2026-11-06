package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/pkg/factory"
)

type UpfApp struct {
	ctx        context.Context
	wg         sync.WaitGroup
	cfg        *factory.Config
	driver     forwarder.Driver
	pfcpServer *pfcp.PfcpServer
	eesServer  *ees.Server
}

func NewApp(cfg *factory.Config) (*UpfApp, error) {
	upf := &UpfApp{
		cfg: cfg,
	}
	upf.SetLogLevel(cfg.Logger.Level)
	upf.SetLogReportCaller(cfg.Logger.ReportCaller)
	return upf, nil
}

func (u *UpfApp) Config() *factory.Config {
	return u.cfg
}

func (a *UpfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	logger.Log.SetLevel(lvl)
}

func (a *UpfApp) SetLogReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	logger.Log.SetReportCaller(reportCaller)
}

func (u *UpfApp) Run() error {
	var cancel context.CancelFunc
	u.ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	u.wg.Add(1)
	/* Go Routine is spawned here for listening for cancellation event on
	 * context */
	go u.listenShutdownEvent()

	var err error
	u.driver, err = forwarder.NewDriver(&u.wg, u.cfg)
	if err != nil {
		return err
	}

	u.pfcpServer = pfcp.NewPfcpServer(u.cfg, u.driver)
	u.driver.HandleReport(u.pfcpServer)

	// EES is optional; when disabled nothing below touches the PFCP path. It is
	// set up before the PFCP loop starts because the opt-in UPF-owned URR
	// source is configured on the PFCP server.
	if err := u.initEES(); err != nil {
		return err
	}
	u.pfcpServer.Start(&u.wg)

	logger.MainLog.Infoln("UPF started")

	// Wait for interrupt signal to gracefully shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	// Receive the interrupt signal
	logger.MainLog.Infof("Shutdown UPF ...")
	// Notify each goroutine and wait them stopped
	cancel()
	u.WaitRoutineStopped()
	logger.MainLog.Infof("UPF exited")
	return nil
}

func (u *UpfApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		u.wg.Done()
	}()

	<-u.ctx.Done()
	if u.pfcpServer != nil {
		u.pfcpServer.Stop()
	}
	if u.eesServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := u.eesServer.Shutdown(shutdownCtx); err != nil {
			logger.MainLog.Errorf("EES API Server Shutdown Error: %v", err)
		}
	}
	if u.driver != nil {
		u.driver.Close()
	}
}

func (u *UpfApp) WaitRoutineStopped() {
	u.wg.Wait()
	u.Terminate()
}

func (u *UpfApp) Start() {
	if err := u.Run(); err != nil {
		logger.MainLog.Errorf("UPF Run err: %v", err)
	}
}

func (u *UpfApp) Terminate() {
	logger.MainLog.Infof("Terminating UPF...")
	logger.MainLog.Infof("UPF terminated")
}

// initEES starts the embedded Nupf_EventExposure service. Two independent
// switches start it: ees.enabled (usage from the SMF-provisioned URR 2) and
// ees.upfUrrEnabled (usage from UPF-owned monitoring URRs). With both on the
// two are reported separately. EES only receives usage through a buffer-only
// PFCP hook; it never writes the PFCP queue. With both off nothing below runs.
func (u *UpfApp) initEES() error {
	cfg := u.cfg.EES
	if cfg == nil || (!cfg.Enabled && !cfg.UpfURREnabled) {
		return nil
	}
	logger.MainLog.Infoln("EES supports only the free5GC single-UPF scenario; keep it disabled in ULCL deployments")

	if cfg.UpfURRPeriod < 0 || cfg.UpfURRPeriod > 86400 {
		return fmt.Errorf("ees.upfUrrPeriod must be 0..86400 seconds, got %d", cfg.UpfURRPeriod)
	}

	listenIP, port := cfg.IP, 8088
	if cfg.Port != 0 {
		port = cfg.Port
	}
	store := ees.NewSubscriptionStore("")
	aggregator := ees.NewAggregator(store, ees.NewNotifier(logger.EesLog), logger.EesLog)
	u.pfcpServer.RegisterEESReportHandler(aggregator.PushReportWithContext)
	source, sourceDesc := ees.SourceSMFURR, "SMF URR 2"
	if cfg.UpfURREnabled {
		period := time.Duration(max(cfg.UpfURRPeriod, 1)) * time.Second
		u.pfcpServer.EnableUPFOwnedURRs(store, period)
		source, sourceDesc = ees.SourceUPFURR, fmt.Sprintf("UPF-owned monitoring URR per session, period %v", period)
		if cfg.Enabled {
			source, sourceDesc = ees.SourceBothURRs, "SMF URR 2 and "+sourceDesc
		}
	}

	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		aggregator.Run(u.ctx)
	}()

	listenAddr := fmt.Sprintf("%s:%d", listenIP, port)
	u.eesServer = ees.NewServer(store, logger.EesLog)
	u.eesServer.UseMeasurementSource(source)

	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		if err := u.eesServer.Serve(listenAddr); err != nil {
			logger.MainLog.Errorf("EES API Server Error: %v", err)
		}
	}()

	logger.MainLog.Infof("EES started at %s (per-subscription repPeriod, %s)", listenAddr, sourceDesc)
	return nil
}
