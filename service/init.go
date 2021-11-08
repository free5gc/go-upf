package service

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/path_util"

	"github.com/m-asama/upf/context"
	"github.com/m-asama/upf/factory"
	"github.com/m-asama/upf/forwarder"
	"github.com/m-asama/upf/logger"
	"github.com/m-asama/upf/pfcp"
)

type UPF struct{}

type (
	Config struct {
		upfcfg string
	}
)

var config Config

var upfCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "upfcfg",
		Usage: "config file",
	},
}

var initLog *logrus.Entry

var pfcpServers []*pfcp.PfcpServer

func init() {
	initLog = logger.InitLog
	pfcpServers = make([]*pfcp.PfcpServer, 0)
}

func (*UPF) GetCliCmd() (flags []cli.Flag) {
	return upfCLi
}

func (upf *UPF) Initialize(c *cli.Context) error {
	config = Config{
		upfcfg: c.String("upfcfg"),
	}

	if config.upfcfg != "" {
		if err := factory.InitConfigFactory(config.upfcfg); err != nil {
			return err
		}
	} else {
		DefaultUpfConfigPath := path_util.Free5gcPath("free5gc/config/upfcfg.yaml")
		if err := factory.InitConfigFactory(DefaultUpfConfigPath); err != nil {
			return err
		}
	}

	upf.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	return nil
}

func (upf *UPF) setLogLevel() {
	if factory.UpfConfig.Configuration == nil {
		initLog.Warnln("UPF config without log level setting!!!")
		return
	}

	if factory.UpfConfig.Configuration.DebugLevel != "" {
		if level, err := logrus.ParseLevel(factory.UpfConfig.Configuration.DebugLevel); err != nil {
			initLog.Warnf("UPF Log level [%s] is invalid, set to [info] level",
				factory.UpfConfig.Configuration.DebugLevel)
			logger.SetLogLevel(logrus.InfoLevel)
		} else {
			initLog.Infof("UPF Log level is set to [%s] level", level)
			logger.SetLogLevel(level)
		}
	} else {
		initLog.Infoln("UPF Log level is default set to [info] level")
		logger.SetLogLevel(logrus.InfoLevel)
	}
	logger.SetReportCaller(factory.UpfConfig.Configuration.ReportCaller)
}

func (upf *UPF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range upf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (upf *UPF) Start() {
	context.InitUpfContext(&factory.UpfConfig)

	initLog.Infoln("Server started")

	var gtpuaddr string
	for _, gtpu := range factory.UpfConfig.Configuration.Gtpu {
		gtpuaddr = fmt.Sprintf("%s:%v", gtpu.Addr, 2152)
		initLog.Infof("GTP Address: %q\n", gtpuaddr)
		break
	}
	if gtpuaddr == "" {
		initLog.Errorln("not found GTP address")
		return
	}
	driver, err := forwarder.OpenGtp5g(gtpuaddr)
	if err != nil {
		initLog.Errorln(err)
		return
	}
	defer driver.Close()

	link := driver.Link()
	for _, dnn := range factory.UpfConfig.Configuration.DnnList {
		_, dst, err := net.ParseCIDR(dnn.Cidr)
		if err != nil {
			initLog.Errorln(err)
			continue
		}
		route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
		err = netlink.RouteAdd(&route)
		if err != nil {
			initLog.Errorln(err)
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
		//os.Exit(0)
	}()

	for _, configPfcp := range factory.UpfConfig.Configuration.Pfcp {
		pfcpServer := pfcp.NewPfcpServer(configPfcp.Addr, driver)
		pfcpServer.Start()
		pfcpServers = append(pfcpServers, pfcpServer)
	}

	//time.Sleep(1000 * time.Millisecond)

	<-exit
}

func (upf *UPF) Terminate() {
	logger.InitLog.Infof("Terminating UPF...")
	for _, pfcpServer := range pfcpServers {
		pfcpServer.Terminate()
	}
}

func (upf *UPF) Exec(c *cli.Context) error {
	return nil
}
