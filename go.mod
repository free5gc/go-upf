module github.com/m-asama/upf

go 1.14

//replace github.com/free5gc/logger_util => ../logger_util

require (
	github.com/antonfisher/nested-logrus-formatter v1.3.0
	github.com/free5gc/logger_conf v1.0.0
	github.com/free5gc/logger_util v1.0.0
	github.com/free5gc/path_util v1.0.0
	github.com/free5gc/version v1.0.0
	github.com/sirupsen/logrus v1.7.0
	github.com/urfave/cli v1.22.4
	github.com/wmnsk/go-pfcp v0.0.11
	gopkg.in/yaml.v2 v2.4.0
)
