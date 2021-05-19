package factory

const (
	UPF_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	UPF_DEFAULT_IPV4 = "127.0.0.8"
	UPF_DEFAULT_PORT = "8805"
)

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

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
