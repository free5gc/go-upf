package factory

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/go-upf/internal/logger"
)

var UpfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string, cfg *Config) error {
	if f == "" {
		// Use default config path
		f = UpfDefaultConfigPath
	}

	if content, err := ioutil.ReadFile(f); err != nil {
		return fmt.Errorf("[Factory] %+v", err)
	} else {
		logger.CfgLog.Infof("Read config from [%s]", f)
		if yamlErr := yaml.Unmarshal(content, cfg); yamlErr != nil {
			return fmt.Errorf("[Factory] %+v", yamlErr)
		}
	}

	return nil
}

func CheckConfigVersion(cfg *Config) error {
	currentVersion := cfg.Version()
	if currentVersion != UpfExpectedConfigVersion {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, UpfExpectedConfigVersion)
	}
	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}

func ReadConfig(cfgPath string) (*Config, error) {
	cfg := &Config{}
	if err := InitConfigFactory(cfgPath, cfg); err != nil {
		return nil, fmt.Errorf("ReadConfig [%s] Error: %+v", cfgPath, err)
	}
	if err := CheckConfigVersion(cfg); err != nil {
		return nil, err
	}

	cfg.Print()
	return cfg, nil
}
