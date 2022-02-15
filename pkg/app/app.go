package app

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/free5gc/go-upf/internal/context"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/pkg/factory"
)

type UPF struct{}

var pfcpServers []*pfcp.PfcpServer

func init() {
	pfcpServers = make([]*pfcp.PfcpServer, 0)
}

func (upf *UPF) Initialize(c *cli.Context) error {
	upf.setLogLevel()
	return nil
}

func (upf *UPF) setLogLevel() {
	cfg := factory.UpfConfig.Configuration
	if cfg == nil {
		logger.InitLog.Warnln("UPF config without log level setting!!!")
		return
	}
	setLoggerLogLevel("UPF", cfg.DebugLevel, cfg.ReportCaller,
		logger.SetLogLevel, logger.SetReportCaller)
}

func setLoggerLogLevel(loggerName, DebugLevel string, reportCaller bool,
	logLevelFn func(l logrus.Level), reportCallerFn func(b bool)) {
	if DebugLevel != "" {
		if level, err := logrus.ParseLevel(DebugLevel); err != nil {
			logger.InitLog.Warnf("%s Log level [%s] is invalid, set to [info] level",
				loggerName, DebugLevel)
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

func (upf *UPF) Start() {
	context.InitUpfContext(&factory.UpfConfig)

	logger.InitLog.Infoln("Server started")

	var gtpuaddr string
	for _, gtpu := range factory.UpfConfig.Configuration.Gtpu {
		gtpuaddr = fmt.Sprintf("%s:%d", gtpu.Addr, factory.UpfGtpDefaultPort)
		logger.InitLog.Infof("GTP Address: %q", gtpuaddr)
		break
	}
	if gtpuaddr == "" {
		logger.InitLog.Errorln("not found GTP address")
		return
	}
	driver, err := forwarder.OpenGtp5g(gtpuaddr)
	if err != nil {
		logger.InitLog.Errorln(err)
		return
	}
	defer driver.Close()

	link := driver.Link()
	for _, dnn := range factory.UpfConfig.Configuration.DnnList {
		_, dst, err := net.ParseCIDR(dnn.Cidr)
		if err != nil {
			logger.InitLog.Errorln(err)
			continue
		}
		err = link.RouteAdd(dst)
		if err != nil {
			logger.InitLog.Errorln(err)
			return
		}
		break
	}

	exit := make(chan bool)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		upf.Terminate()
		exit <- true
		// os.Exit(0)
	}()

	for _, configPfcp := range factory.UpfConfig.Configuration.Pfcp {
		pfcpServer := pfcp.NewPfcpServer(configPfcp.Addr, driver)
		pfcpServer.Start()
		pfcpServers = append(pfcpServers, pfcpServer)
	}

	// time.Sleep(1000 * time.Millisecond)

	<-exit
}

func (upf *UPF) Terminate() {
	logger.InitLog.Infof("Terminating UPF...")
	for _, pfcpServer := range pfcpServers {
		pfcpServer.Terminate()
	}
}
