package factory

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/go-upf/logger"
)

var (
	UpfConfig Config
)

func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		UpfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &UpfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := UpfConfig.GetVersion()

	if currentVersion != UPF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("UPF config version is [%s], but expected is [%s].",
			currentVersion, UPF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("UPF config version [%s]", currentVersion)

	return nil
}
