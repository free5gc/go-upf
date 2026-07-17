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
	"github.com/free5gc/go-upf/internal/forwarder/perio"
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
		// Use a short timeout for API server shutdown
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

func (u *UpfApp) Run() error {
	var cancel context.CancelFunc

	u.ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	u.wg.Add(1)
	// Go Routine is spawned here for listening for cancellation event on
	// context
	go u.listenShutdownEvent()
	// ... (Original context setting) ...

	var err error
	u.driver, err = forwarder.NewDriver(&u.wg, u.cfg)
	if err != nil {
		return err
	}

	u.pfcpServer = pfcp.NewPfcpServer(u.cfg, u.driver)

	// [New] Dispatcher wiring
	reportDispatcher := NewDispatcher(u.pfcpServer)
	u.driver.HandleReport(reportDispatcher)

	u.pfcpServer.Start(&u.wg)

	// [New] Initialize EES if enabled
	if err := u.initEES(reportDispatcher); err != nil {
		return err
	}

	logger.MainLog.Infoln("UPF started")

	// ... (Subsequent Signal handling remains unchanged)
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

func (u *UpfApp) initEES(reportDispatcher *Dispatcher) error {
	if u.cfg.EES == nil || !u.cfg.EES.Enabled {
		return nil
	}

	logger.MainLog.Infoln("Starting EES Module (Pure Push Mode)...")

	// 1. Use existing EesLog
	eesLogger := logger.EesLog

	// 2. Create Store / Notifier / Aggregator
	subscriptionStore := ees.NewSubscriptionStore("")
	notifier := ees.NewNotifier(eesLogger)

	period := 10
	if u.cfg.EES.PeriodSec > 0 {
		period = u.cfg.EES.PeriodSec
	}

	// Pure Push mode: Reports come from kernel
	localNode := u.pfcpServer.GetLocalNode()
	sessionProvider := localNode

	// Get perioServer from driver for URR period queries
	var perioServer *perio.Server
	if gtp5gDriver, ok := u.driver.(*forwarder.Gtp5g); ok {
		perioServer = gtp5gDriver.GetPerioServer()
	}

	aggregator := ees.NewAggregator(
		subscriptionStore,
		time.Duration(period)*time.Second,
		notifier,
		eesLogger,
		sessionProvider,
		perioServer, // Pass perioServer for period validation
	)

	// 3. Register EES Handler to Dispatcher
	eesHandler := ees.NewHandler(aggregator, eesLogger)
	reportDispatcher.RegisterEESHandler(eesHandler)

	// Set perioServer callbacks
	if perioServer != nil {
		// Register callback to adjust aggregator period when URR is added
		perioServer.SetOnURRAdded(func(urrid uint32, period time.Duration) {
			// Only adjust for URR 2 (the periodic measurement URR)
			if urrid == 2 {
				logger.MainLog.Infof("EES: URR %d added with period %v, triggering aggregator adjustment", urrid, period)
				aggregator.AdjustReportPeriod(period)
			}
		})
	}

	// 4. Start Aggregator (processes buffered reports periodically)
	go aggregator.Run(u.ctx)

	// 5. Start API Server (simplified - no Shadow URR provisioning)
	port := u.cfg.EES.Port
	if port == 0 {
		port = 8088
	}
	listenAddr := fmt.Sprintf("%s:%d", u.cfg.EES.IP, port)
	u.eesServer = ees.NewServer(subscriptionStore, aggregator, eesLogger)

	go func() {
		if err := u.eesServer.Serve(listenAddr); err != nil {
			logger.MainLog.Errorf("EES API Server Error: %v", err)
		}
	}()

	logger.MainLog.Infof("EES started at %s with period %ds (Pure Push Mode - SMF URR)", listenAddr, period)
	return nil
}
