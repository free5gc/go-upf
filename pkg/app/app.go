package app

import (
	"context"
	"fmt"
	"net"
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
	ctx         context.Context
	wg          sync.WaitGroup
	cfg         *factory.Config
	pfcpServers []*pfcp.PfcpServer
}

func NewUpf(cfg *factory.Config) (*UPF, error) {
	upf := &UPF{
		cfg:         cfg,
		pfcpServers: make([]*pfcp.PfcpServer, 0),
	}

	setLoggerLogLevel("UPF", cfg.DebugLevel, cfg.ReportCaller,
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

func setLoggerLogLevel(loggerName, debugLevel string, reportCaller bool,
	logLevelFn func(l logrus.Level), reportCallerFn func(b bool)) {
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

	var gtpuaddr string
	for _, gtpu := range u.cfg.Gtpu {
		gtpuaddr = fmt.Sprintf("%s:%d", gtpu.Addr, factory.UpfGtpDefaultPort)
		logger.InitLog.Infof("GTP Address: %q", gtpuaddr)
		break
	}
	if gtpuaddr == "" {
		return fmt.Errorf("not found GTP address")
	}
	driver, err := forwarder.OpenGtp5g(gtpuaddr)
	if err != nil {
		return err
	}
	defer driver.Close()

	link := driver.Link()
	for _, dnn := range u.cfg.DnnList {
		_, dst, err := net.ParseCIDR(dnn.Cidr)
		if err != nil {
			logger.InitLog.Errorln(err)
			continue
		}
		err = link.RouteAdd(dst)
		if err != nil {
			return err
		}
		break
	}

	for _, cfgPfcp := range u.cfg.Pfcp {
		pfcpServer := pfcp.NewPfcpServer(cfgPfcp.Addr, driver)
		pfcpServer.Start(&u.wg)
		u.pfcpServers = append(u.pfcpServers, pfcpServer)
	}

	logger.InitLog.Infoln("Server started")

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
	for _, pfcpServer := range u.pfcpServers {
		pfcpServer.Terminate()
	}
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
