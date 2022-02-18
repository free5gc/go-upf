package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var (
	log      *logrus.Logger
	MainLog  *logrus.Entry
	InitLog  *logrus.Entry
	CfgLog   *logrus.Entry
	PfcpLog  *logrus.Entry
	CtxLog   *logrus.Entry
	BuffLog  *logrus.Entry
	SessLog  *logrus.Entry
	Gtp5gLog *logrus.Entry
)

const (
	FieldListenAddr string = "listen_addr"
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category", FieldListenAddr},
	}

	MainLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Main"})
	InitLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Cfg"})
	PfcpLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Pfcp"})
	CtxLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Ctx"})
	BuffLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Buff"})
	SessLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Sess"})
	Gtp5gLog = log.WithFields(logrus.Fields{"component": "UPF", "category": "Gtp5g"})
}

func LogFileHook(logNfPath string, log5gcPath string) error {
	if fullPath, err := logger_util.CreateFree5gcLogFile(log5gcPath); err == nil {
		if fullPath != "" {
			free5gcLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
			if err != nil {
				return hookErr
			}
			log.Hooks.Add(free5gcLogHook)
		}
	} else {
		return err
	}

	if fullPath, err := logger_util.CreateNfLogFile(logNfPath, "upf.log"); err == nil {
		selfLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
		if err != nil {
			return hookErr
		}
		log.Hooks.Add(selfLogHook)
	} else {
		return err
	}

	return nil
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(enable bool) {
	log.SetReportCaller(enable)
}
