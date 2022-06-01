package app

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/pkg/factory"
)

type UPF struct {
	ctx        context.Context
	wg         sync.WaitGroup
	cfg        *factory.Config
	driver     forwarder.Driver
	pfcpServer *pfcp.PfcpServer
}

func NewUpf(cfg *factory.Config) (*UPF, error) {
	upf := &UPF{
		cfg: cfg,
	}

	setLoggerLogLevel("UPF", cfg.Logger.Level, cfg.Logger.ReportCaller,
		logger.SetLogLevel, logger.SetReportCaller)
	return upf, nil
}

func (u *UPF) Config() *factory.Config {
	return u.cfg
}

func (u *UPF) SetLogLevel(lvl string, caller bool) {
	setLoggerLogLevel("UPF", lvl, caller,
		logger.SetLogLevel, logger.SetReportCaller)
}

func setLoggerLogLevel(
	loggerName, debugLevel string, reportCaller bool,
	logLevelFn func(l logrus.Level),
	reportCallerFn func(b bool),
) {
	if debugLevel != "" {
		if level, err := logrus.ParseLevel(debugLevel); err != nil {
			logger.InitLog.Warnf("%s Log level [%s] is invalid, set to [info] level",
				loggerName, debugLevel)
			logLevelFn(logrus.InfoLevel)
		} else {
			logger.InitLog.Infof("%s Log level is set to [%s] level", loggerName, level)
			logLevelFn(level)
		}
	} else {
		logger.InitLog.Infof("%s Log level is default set to [info] level", loggerName)
		logLevelFn(logrus.InfoLevel)
	}
	reportCallerFn(reportCaller)
}

func (u *UPF) Run() error {
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
	u.pfcpServer.Start(&u.wg)

	logger.InitLog.Infoln("UPF started")

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

func (u *UPF) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		u.wg.Done()
	}()

	<-u.ctx.Done()
	u.pfcpServer.Stop()
	u.driver.Close()
}

func (u *UPF) WaitRoutineStopped() {
	u.wg.Wait()
	u.Terminate()
}

func (u *UPF) Start() {
	if err := u.Run(); err != nil {
		logger.InitLog.Errorf("UPF Run err: %v", err)
	}
}

func (u *UPF) Terminate() {
	logger.MainLog.Infof("Terminating UPF...")
	logger.MainLog.Infof("UPF terminated")
}
