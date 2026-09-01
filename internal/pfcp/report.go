package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

func (h *MessageHandler) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	sess, err := h.node.Session(seid)
	if err != nil {
		h.log.Errorln(err)
		return nil, false
	}
	return sess.Pop(pdrid)
}

func (h *MessageHandler) ServeReport(sr *report.SessReport) {
	h.log.Debugf("ServeReport: SEID(%#x)", sr.SEID)
	sess, err := h.node.Session(sr.SEID)
	if err != nil {
		h.log.Errorln(err)
		return
	}

	addr := fmt.Sprintf("%s:%d", sess.association.PeerNodeID, factory.UpfPfcpDefaultPort)
	laddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return
	}

	var usars []report.USAReport
	for _, rpt := range sr.Reports {
		switch r := rpt.(type) {
		case report.DLDReport:
			h.log.Debugf("ServeReport: SEID(%#x), type(%s)", sr.SEID, r.Type())
			if r.Action&report.APPLY_ACT_BUFF != 0 && len(r.BufPkt) > 0 {
				sess.Push(r.PDRID, r.BufPkt)
			}
			if r.Action&report.APPLY_ACT_NOCP == 0 {
				return
			}
			err := h.serveDLDReport(laddr, sr.SEID, r.PDRID)
			if err != nil {
				h.log.Errorln(err)
			}
		case report.USAReport:
			h.log.Debugf("ServeReport: SEID(%#x), type(%s)", sr.SEID, r.Type())
			usars = append(usars, r)
		default:
			h.log.Warnf("Unsupported Report: SEID(%#x), type(%d)", sr.SEID, rpt.Type())
		}
	}

	if len(usars) > 0 {
		err := h.serveUSAReport(laddr, sr.SEID, usars)
		if err != nil {
			h.log.Errorln(err)
		}
	}
}

func (h *MessageHandler) serveDLDReport(addr net.Addr, lSeid uint64, pdrid uint16) error {
	h.log.Infoln("serveDLDReport")

	sess, err := h.node.Session(lSeid)
	if err != nil {
		return errors.Wrap(err, "serveDLDReport")
	}

	req := message.NewSessionReportRequest(
		0,
		0,
		sess.RemoteID,
		0,
		0,
		ie.NewReportType(0, 0, 0, 1),
		ie.NewDownlinkDataReport(
			ie.NewPDRID(pdrid),
			/*
				ie.NewDownlinkDataServiceInformation(
					true,
					true,
					ppi,
					qfi,
				),
			*/
		),
	)

	err = h.transport.sendReqTo(req, addr)
	return errors.Wrap(err, "serveDLDReport")
}

func (h *MessageHandler) serveUSAReport(addr net.Addr, lSeid uint64, usars []report.USAReport) error {
	h.log.Infoln("serveUSAReport")

	sess, err := h.node.Session(lSeid)
	if err != nil {
		return errors.Wrap(err, "serveUSAReport")
	}

	req := message.NewSessionReportRequest(
		0,
		0,
		sess.RemoteID,
		0,
		0,
		ie.NewReportType(0, 0, 1, 0),
	)
	for _, r := range usars {
		urrInfo, ok := sess.URRIDs[r.URRID]
		if !ok {
			sess.log.Warnf("serveUSAReport: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		req.UsageReport = append(req.UsageReport,
			ie.NewUsageReportWithinSessionReportRequest(
				r.IEsWithinSessReportReq(
					urrInfo.MeasureMethod, urrInfo.MeasureInformation)...,
			))
	}

	err = h.transport.sendReqTo(req, addr)
	return errors.Wrap(err, "serveUSAReport")
}
