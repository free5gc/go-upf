package forwarder

import (
	"fmt"
	"net"
	"sync"

	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

type Driver interface {
	Close()

	// QueryURR is used for terminal reporting when a PDR releases its last URR reference.
	QueryURR(uint64, uint32) ([]report.USAReport, error)

	HandleReport(report.Handler)

	// Execution plans are an implementation detail shared only within forwarder.
	sessionBackend
}

// gtpuInterface is the GTP-U address, the MTU and the gtp5g device of the first interface of gtpu.ifList: the
// device that its ifname names, or DefaultLinkName.
func gtpuInterface(ifList []factory.IfInfo) (addr string, mtu uint32, linkName string) {
	linkName = DefaultLinkName
	if len(ifList) == 0 {
		return "", 0, linkName
	}
	ifInfo := ifList[0]
	if ifInfo.IfName != "" {
		linkName = ifInfo.IfName
	}
	return fmt.Sprintf("%s:%d", ifInfo.Addr, factory.UpfGtpDefaultPort), ifInfo.MTU, linkName
}

func NewDriver(wg *sync.WaitGroup, cfg *factory.Config) (Driver, error) {
	cfgGtpu := cfg.Gtpu
	if cfgGtpu == nil {
		return nil, errors.Errorf("no Gtpu config")
	}

	logger.MainLog.Infof("starting Gtpu Forwarder [%s]", cfgGtpu.Forwarder)
	if cfgGtpu.Forwarder == "gtp5g" {
		gtpuAddr, mtu, linkName := gtpuInterface(cfgGtpu.IfList)
		if gtpuAddr == "" {
			return nil, errors.Errorf("not found GTP address")
		}
		logger.MainLog.Infof("GTP Address: %q, gtp5g device %q", gtpuAddr, linkName)
		driver, err := OpenGtp5g(wg, gtpuAddr, mtu, linkName)
		if err != nil {
			return nil, errors.Wrap(err, "open Gtp5g")
		}

		driver.iptables = NewIptablesManager()
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
			if dnn.NatIfName != "" || dnn.NatIfCIDR != "" {
				err = driver.iptables.AddDNNRules(
					dnn.Cidr,
					dnn.NatIfName,
					dnn.NatIfCIDR,
					dnn.IPForwardEnable,
					dnn.TCPMss,
				)
				if err != nil {
					driver.Close()
					return nil, err
				}
			}
		}
		return driver, nil
	}
	return nil, errors.Errorf("not support forwarder:%q", cfgGtpu.Forwarder)
}
