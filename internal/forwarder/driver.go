package forwarder

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

type Driver interface {
	Close()

	CreatePDR(uint64, *ie.IE) error
	UpdatePDR(uint64, *ie.IE) error
	RemovePDR(uint64, *ie.IE) error

	CreateFAR(uint64, *ie.IE) error
	UpdateFAR(uint64, *ie.IE) error
	RemoveFAR(uint64, *ie.IE) error

	CreateQER(uint64, *ie.IE) error
	UpdateQER(uint64, *ie.IE) error
	RemoveQER(uint64, *ie.IE) error

	CreateURR(uint64, *ie.IE) error
	UpdateURR(uint64, *ie.IE) error
	RemoveURR(uint64, *ie.IE) (*report.USAReport, error)

	CreateBAR(uint64, *ie.IE) error
	UpdateBAR(uint64, *ie.IE) error
	RemoveBAR(uint64, *ie.IE) error

	HandleReport(report.Handler)
}

func NewDriver(wg *sync.WaitGroup, cfg *factory.Config) (Driver, error) {
	cfgGtpu := cfg.Gtpu
	if cfgGtpu == nil {
		return nil, errors.Errorf("no Gtpu config")
	}

	logger.MainLog.Infof("starting Gtpu Forwarder [%s]", cfgGtpu.Forwarder)
	if cfgGtpu.Forwarder == "gtp5g" {
		cmd := exec.Command("modinfo", "gtp5g", "-F", "version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to get gtp5g version")
		}
		expVer, err := version.NewVersion(expectedGtp5gVersion)
		if err != nil {
			return nil, errors.Wrapf(err, "parse expectedGtp5gVersion err")
		}
		outVer := strings.TrimSpace(string(out))
		nowVer, err := version.NewVersion(outVer)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to parse gtp5g version(%s)", outVer)
		}
		if nowVer.LessThan(expVer) {
			return nil, errors.Errorf(
				"gtp5g version should be >= %s, please upgrade it",
				expectedGtp5gVersion)
		}

		var gtpuAddr string
		var mtu uint32
		for _, ifInfo := range cfgGtpu.IfList {
			mtu = ifInfo.MTU
			gtpuAddr = fmt.Sprintf("%s:%d", ifInfo.Addr, factory.UpfGtpDefaultPort)
			logger.MainLog.Infof("GTP Address: %q", gtpuAddr)
			break
		}
		if gtpuAddr == "" {
			return nil, errors.Errorf("not found GTP address")
		}
		driver, err := OpenGtp5g(wg, gtpuAddr, mtu)
		if err != nil {
			return nil, errors.Wrap(err, "open Gtp5g")
		}

		link := driver.Link()
		for _, dnn := range cfg.DnnList {
			_, dst, err := net.ParseCIDR(dnn.Cidr)
			if err != nil {
				logger.MainLog.Errorln(err)
				continue
			}
			err = link.RouteAdd(dst)
			if err != nil {
				driver.Close()
				return nil, err
			}
			break
		}
		return driver, nil
	}
	return nil, errors.Errorf("not support forwarder:%q", cfgGtpu.Forwarder)
}
