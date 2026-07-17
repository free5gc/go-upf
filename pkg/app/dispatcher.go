package app

import (
	"github.com/free5gc/go-upf/internal/report"
)

// Dispatcher implements report.Handler and multicasts reports to registered handlers.
// It allows both PFCP (SMF) and EES to receive usage reports.
type Dispatcher struct {
	// Primary: PFCP Server (also handles buffering)
	pfcpHandler report.Handler
	// Secondary: EES Handler (optional, only receives reports)
	eesHandler report.Handler
}

// NewDispatcher creates a dispatcher.
func NewDispatcher(pfcpHandler report.Handler) *Dispatcher {
	return &Dispatcher{
		pfcpHandler: pfcpHandler,
	}
}

// RegisterEESHandler registers the EES handler.
func (d *Dispatcher) RegisterEESHandler(handler report.Handler) {
	d.eesHandler = handler
}

// NotifySessReport multicasts the report to all registered handlers.
// Pure Push Mode: All USAReports are forwarded to both handlers.
// - PFCP handler: forwards to SMF (N4)
// - EES handler: aggregates for event exposure (filters URRID == 2 internally)
func (d *Dispatcher) NotifySessReport(sessRpt report.SessReport) {
	// Dispatch to PFCP (N4) - all reports
	if d.pfcpHandler != nil {
		d.pfcpHandler.NotifySessReport(sessRpt)
	}

	// Dispatch to EES - all reports (EES aggregator filters by URRID == 2)
	if d.eesHandler != nil {
		d.eesHandler.NotifySessReport(sessRpt)
	}
}

// PopBufPkt delegates buffering logic exclusively to the PFCP handler.
// EES does not handle buffering.
func (d *Dispatcher) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	if d.pfcpHandler != nil {
		return d.pfcpHandler.PopBufPkt(seid, pdrid)
	}
	return nil, false
}
