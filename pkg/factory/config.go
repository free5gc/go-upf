package factory

import (
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/go-upf/internal/logger"
)

const (
	UpfDefaultConfigPath = "./config/upfcfg.yaml"
	UpfDefaultIPv4       = "127.0.0.8"
	UpfPfcpDefaultPort   = 8805
	UpfGtpDefaultPort    = 2152
)

type Config struct {
	Version     string    `yaml:"version"     valid:"required,in(1.0.3)"`
	Description string    `yaml:"description" valid:"optional"`
	Pfcp        *Pfcp     `yaml:"pfcp"        valid:"required"`
	Gtpu        *Gtpu     `yaml:"gtpu"        valid:"required"`
	DnnList     []DnnList `yaml:"dnnList"     valid:"required"`
	Logger      *Logger   `yaml:"logger"      valid:"required"`
	// NrfUri is optional. When set, the UPF registers its Nupf_EventExposure service with the NRF.
	NrfUri string `yaml:"nrfUri" valid:"optional"`
}

const (
	// UpfEventExposurePort is the port for the Nupf_EventExposure HTTP server.
	UpfEventExposurePort = 8090
	// UpfMonitoringURRIDBase is the starting URR ID for UPF-self-allocated monitoring URRs.
	// URR IDs above this value are reserved for Event Exposure monitoring, avoiding
	// collision with SMF-allocated URR IDs which typically start at low values.
	UpfMonitoringURRIDBase uint32 = 0xF0000001
)

type Pfcp struct {
	Addr           string        `yaml:"addr"           valid:"required,host"`
	NodeID         string        `yaml:"nodeID"         valid:"required,host"`
	RetransTimeout time.Duration `yaml:"retransTimeout" valid:"required"`
	MaxRetrans     uint8         `yaml:"maxRetrans"     valid:"optional"`
}

type Gtpu struct {
	Forwarder string   `yaml:"forwarder" valid:"required,in(gtp5g)"`
	IfList    []IfInfo `yaml:"ifList"    valid:"optional"`
}

type IfInfo struct {
	Addr   string `yaml:"addr"   valid:"required,host"`
	Type   string `yaml:"type"   valid:"required,in(N3|N9)"`
	Name   string `yaml:"name"   valid:"optional"`
	IfName string `yaml:"ifname" valid:"optional"`
	MTU    uint32 `yaml:"mtu"    valid:"optional"`
}

type DnnList struct {
	Dnn       string `yaml:"dnn"       valid:"required"`
	Cidr      string `yaml:"cidr"      valid:"required,cidr"`
	NatIfName string `yaml:"natifname" valid:"optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable"       valid:"optional"`
	Level        string `yaml:"level"        valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"optional"`
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
