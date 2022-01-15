package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/free5gc/version"

	"github.com/free5gc/go-upf/logger"
	"github.com/free5gc/go-upf/service"
)

var UPF = &service.UPF{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "upf"
	fmt.Print(app.Name, "\n")
	appLog.Infoln("UPF version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -upfcfg upf configuration file"
	app.Action = action
	app.Flags = UPF.GetCliCmd()
	rand.Seed(time.Now().UnixNano())

	if err := app.Run(os.Args); err != nil {
		appLog.Errorf("UPF Run Error: %v", err)
	}
}

func action(c *cli.Context) error {
	if err := UPF.Initialize(c); err != nil {
		appLog.Errorf("%+v", err)
		return fmt.Errorf("Failed to initialize !!")
	}

	UPF.Start()

	return nil
}
