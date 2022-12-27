module github.com/free5gc/go-upf

go 1.14

require (
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/davecgh/go-spew v1.1.1
	github.com/free5gc/go-gtp5gnl v1.4.3
	github.com/free5gc/util v1.0.3
	github.com/hashicorp/go-version v1.6.0
	github.com/khirono/go-nl v1.0.5
	github.com/khirono/go-rtnllink v1.1.1
	github.com/khirono/go-rtnlroute v1.0.1
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.5
	github.com/wmnsk/go-pfcp v0.0.17-0.20221027122420-36112307f93a
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/free5gc/go-gtp5gnl => /home/free5gc/free5gc/go-gtp5gnl
