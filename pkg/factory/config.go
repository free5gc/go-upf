package factory

import (
	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/go-upf/internal/logger"
)

const (
	UpfDefaultConfigPath     = "./config/upfcfg.yaml"
	UpfExpectedConfigVersion = "1.0.0"
	UpfDefaultIPv4           = "127.0.0.8"
	UpfPfcpDefaultPort       = 8805
	UpfGtpDefaultPort        = 2152
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

type Configuration struct {
	DebugLevel   string    `yaml:"debugLevel"`
	ReportCaller bool      `yaml:"ReportCaller"`
	Pfcp         []Pfcp    `yaml:"pfcp"`
	Gtpu         []Gtpu    `yaml:"gtpu"`
	DnnList      []DnnList `yaml:"dnn_list"`
}

type Pfcp struct {
	Addr string `yaml:"addr"`
}

type Gtpu struct {
	Addr   string `yaml:"addr"`
	Name   string `yaml:"name,omitempty"`
	IfName string `yaml:"ifname,omitempty"`
}

type DnnList struct {
	Dnn       string `yaml:"dnn"`
	Cidr      string `yaml:"cidr"`
	NatIfName string `yaml:"natifname,omitempty"`
}

func (c *Config) Version() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) Print() {
	spew.Config.Indent = "\t"
	str := spew.Sdump(c.Configuration)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}
