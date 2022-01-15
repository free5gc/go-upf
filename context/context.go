package context

import (
	"github.com/free5gc/go-upf/factory"
	"github.com/free5gc/go-upf/logger"
)

func init() {
}

var upfContext UPFContext

type UPFContext struct {
}

func InitUpfContext(config *factory.Config) {
	if config == nil {
		logger.CtxLog.Error("Config is nil")
		return
	}

	logger.CtxLog.Infof("upfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	if configuration == nil {
		logger.CtxLog.Error("Configuration is nil")
		return
	}

	configPfcp := configuration.Pfcp
	if configPfcp == nil {
		logger.CtxLog.Error("Pfcp is nil")
		return
	}
}

func UPF_Self() *UPFContext {
	return &upfContext
}
