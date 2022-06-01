package factory

import (
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/go-upf/internal/logger"
)

const (
	UpfDefaultConfigPath     = "./config/upfcfg.yaml"
	UpfExpectedConfigVersion = "1.0.2"
	UpfDefaultIPv4           = "127.0.0.8"
	UpfPfcpDefaultPort       = 8805
	UpfGtpDefaultPort        = 2152
)

type Config struct {
	Version      string    `yaml:"version,omitempty"`
	Description  string    `yaml:"description,omitempty"`
	Pfcp         *Pfcp     `yaml:"pfcp"`
	Gtpu         *Gtpu     `yaml:"gtpu"`
	DnnList      []DnnList `yaml:"dnnList"`
	DebugLevel   string    `yaml:"debugLevel"`
	ReportCaller bool      `yaml:"reportCaller"`
}

type Pfcp struct {
	Addr           string        `yaml:"addr"`
	NodeID         string        `yaml:"nodeID"`
	RetransTimeout time.Duration `yaml:"retransTimeout"`
	MaxRetrans     uint8         `yaml:"maxRetrans"`
}

type Gtpu struct {
	Forwarder string   `yaml:"forwarder"`
	IfList    []IfInfo `yaml:"ifList"`
}

type IfInfo struct {
	Addr   string `yaml:"addr"`
	Type   string `yaml:"type,omitempty"`
	Name   string `yaml:"name,omitempty"`
	IfName string `yaml:"ifname,omitempty"`
}

type DnnList struct {
	Dnn       string `yaml:"dnn"`
	Cidr      string `yaml:"cidr"`
	NatIfName string `yaml:"natifname,omitempty"`
}

func (c *Config) GetVersion() string {
	return c.Version
}

func (c *Config) Print() {
	spew.Config.Indent = "\t"
	str := spew.Sdump(c)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}
