package app

import (
	"net"

	"github.com/free5gc/go-upf/internal/exposure"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/internal/report"
)

// ReportMultiplexer implements report.Handler and multiplexes session reports
// between the exposure server (monitoring URRs) and the PFCP server (SMF-allocated URRs).
//
// The exposure server's HandleReport is called first. If it claims the report as
// fully consumed (all reports in the SessReport were monitoring URRs), the PFCP
// server is not notified. Otherwise the PFCP server handles it normally.
type ReportMultiplexer struct {
	pfcpServer     *pfcp.PfcpServer
	exposureServer *exposure.Server
}

// NewReportMultiplexer creates a multiplexer that routes reports.
func NewReportMultiplexer(pfcpServer *pfcp.PfcpServer, exposureServer *exposure.Server) *ReportMultiplexer {
	return &ReportMultiplexer{
		pfcpServer:     pfcpServer,
		exposureServer: exposureServer,
	}
}

// NotifySessReport implements report.Handler. Reports belonging to monitoring URRs
// are forwarded to the exposure server; all others go to the PFCP server.
func (m *ReportMultiplexer) NotifySessReport(sr report.SessReport) {
	// Split the SessReport: give monitoring URR reports to exposure, rest to pfcp.
	var exposureReports []report.Report
	var pfcpReports []report.Report

	for _, r := range sr.Reports {
		usar, ok := r.(report.USAReport)
		if ok && isMonitoringURR(usar.URRID) {
			exposureReports = append(exposureReports, r)
		} else {
			pfcpReports = append(pfcpReports, r)
		}
	}

	if len(exposureReports) > 0 {
		m.exposureServer.HandleReport(report.SessReport{
			SEID:    sr.SEID,
			Reports: exposureReports,
		})
	}

	if len(pfcpReports) > 0 {
		m.pfcpServer.NotifySessReport(report.SessReport{
			SEID:    sr.SEID,
			Reports: pfcpReports,
		})
	}
}

// PopBufPkt implements report.Handler by delegating to the PFCP server.
func (m *ReportMultiplexer) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	return m.pfcpServer.PopBufPkt(seid, pdrid)
}

// isMonitoringURR returns true if the URR ID is in the monitoring range.
const monitoringURRIDBase uint32 = 0xF0000001

func isMonitoringURR(urrid uint32) bool {
	return urrid >= monitoringURRIDBase
}

// NodeAdapter wraps pfcp.LocalNode to implement exposure.NodeInterface.
type NodeAdapter struct {
	node *pfcp.LocalNode
}

// NewNodeAdapter creates a NodeAdapter.
func NewNodeAdapter(node *pfcp.LocalNode) *NodeAdapter {
	return &NodeAdapter{node: node}
}

// GetAllSessions returns session info for all active PFCP sessions.
func (a *NodeAdapter) GetAllSessions() []exposure.SessionInfo {
	sessions := a.node.GetAllSessions()
	result := make([]exposure.SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		// Copy URR IDs to avoid race conditions (caller may hold no lock)
		urrIDs := make(map[uint32]struct{}, len(s.URRIDs))
		for id := range s.URRIDs {
			urrIDs[id] = struct{}{}
		}
		var ueIP net.IP
		if s.UeIpAddr != nil {
			ueIP = make(net.IP, len(s.UeIpAddr))
			copy(ueIP, s.UeIpAddr)
		}
		result = append(result, exposure.SessionInfo{
			LocalID:        s.LocalID,
			UeIpAddr:       ueIP,
			Dnn:            s.Dnn,
			ExistingURRIDs: urrIDs,
		})
	}
	return result
}
