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
	CfgLog   *logrus.Entry
	PfcpLog  *logrus.Entry
	BuffLog  *logrus.Entry
	FwderLog *logrus.Entry
)

const (
	FieldCategory     string = "category"
	FieldListenAddr   string = "listen_addr"
	FieldRemoteNodeID string = "rnode_id"
	FieldSessionID    string = "session_id"
	FieldTransction   string = "transaction"
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder: []string{
			"component",
			"category",
			FieldListenAddr,
			FieldRemoteNodeID,
			FieldSessionID,
			FieldTransction,
		},
	}

	MainLog = log.WithFields(logrus.Fields{"component": "UPF", FieldCategory: "Main"})
	CfgLog = log.WithFields(logrus.Fields{"component": "UPF", FieldCategory: "Cfg"})
	PfcpLog = log.WithFields(logrus.Fields{"component": "UPF", FieldCategory: "Pfcp"})
	BuffLog = log.WithFields(logrus.Fields{"component": "UPF", FieldCategory: "Buff"})
	FwderLog = log.WithFields(logrus.Fields{"component": "UPF"})
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
