package forwarder

import (
	"fmt"
	"net"
	"sync"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

type Driver interface {
	Close()

	// QueryURR is used internally by diassociateURR when a PDR is removed/updated
	QueryURR(uint64, uint32) ([]report.USAReport, error)

	HandleReport(report.Handler)

	// Plan-based methods for two-phase commit
	// Build*Plan methods parse and validate IEs without executing
	BuildCreatePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error)
	BuildUpdatePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error)
	BuildRemovePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error)

	BuildCreateFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error)
	BuildUpdateFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error)
	BuildRemoveFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error)

	BuildCreateQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error)
	BuildUpdateQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error)
	BuildRemoveQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error)

	BuildCreateURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error)
	BuildUpdateURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error)
	BuildRemoveURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error)
	BuildQueryURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error)

	BuildCreateBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error)
	BuildUpdateBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error)
	BuildRemoveBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error)

	// ExecuteModificationPlan executes all operations in the plan
	// Uses best-effort execution: continues on failure, logs errors
	ExecuteModificationPlan(plan *ModificationPlan) (*ExecutionResult, error)

	// ExecuteEstablishmentPlan executes Create operations for session establishment
	// Uses fail-fast: returns error on first failure
	ExecuteEstablishmentPlan(plan *ModificationPlan) (*ExecutionResult, error)
}

func NewDriver(wg *sync.WaitGroup, cfg *factory.Config) (Driver, error) {
	cfgGtpu := cfg.Gtpu
	if cfgGtpu == nil {
		return nil, errors.Errorf("no Gtpu config")
	}

	logger.MainLog.Infof("starting Gtpu Forwarder [%s]", cfgGtpu.Forwarder)
	if cfgGtpu.Forwarder == "gtp5g" {
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
		}
		return driver, nil
	}
	return nil, errors.Errorf("not support forwarder:%q", cfgGtpu.Forwarder)
}
