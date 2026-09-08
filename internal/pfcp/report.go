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

// The existing TX transaction retains this context until response or timeout.
// Binding the request to its Session prevents a late response from deleting a
// new Session that happens to reuse the same SEIDs.
type sessionReportRequest struct {
	*message.SessionReportRequest
	session *Session
}

func (d *Dispatcher) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	sess, err := d.node.Session(seid)
	if err != nil {
		d.log.Errorln(err)
		return nil, false
	}
	return sess.Pop(pdrid)
}

func (d *Dispatcher) ServeReport(sr *report.SessReport) {
	d.log.Debugf("ServeReport: SEID(%#x)", sr.SEID)
	sess, err := d.node.Session(sr.SEID)
	if err != nil {
		d.log.Errorln(err)
		return
	}

	if sess.closing {
		active, ok := d.node.Association(sess.association.PeerNodeID)
		if !ok || active != sess.association {
			return
		}
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
			if sess.closing {
				continue
			}
			d.log.Debugf("ServeReport: SEID(%#x), type(%s)", sr.SEID, r.Type())
			if r.Action&report.APPLY_ACT_BUFF != 0 && len(r.BufPkt) > 0 {
				sess.Push(r.PDRID, r.BufPkt)
			}
			if r.Action&report.APPLY_ACT_NOCP == 0 {
				return
			}
			err := d.serveDLDReport(laddr, sr.SEID, r.PDRID)
			if err != nil {
				d.log.Errorln(err)
			}
		case report.USAReport:
			d.log.Debugf("ServeReport: SEID(%#x), type(%s)", sr.SEID, r.Type())
			usars = append(usars, r)
		default:
			d.log.Warnf("Unsupported Report: SEID(%#x), type(%d)", sr.SEID, rpt.Type())
		}
	}

	if len(usars) > 0 {
		err := d.serveUSAReport(laddr, sr.SEID, usars)
		if err != nil {
			d.log.Errorln(err)
		}
	}
}

func (d *Dispatcher) serveDLDReport(addr net.Addr, lSeid uint64, pdrid uint16) error {
	d.log.Infoln("serveDLDReport")

	sess, err := d.node.Session(lSeid)
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

	err = d.transport.sendReqTo(&sessionReportRequest{SessionReportRequest: req, session: sess}, addr)
	return errors.Wrap(err, "serveDLDReport")
}

func (d *Dispatcher) serveUSAReport(addr net.Addr, lSeid uint64, usars []report.USAReport) error {
	d.log.Infoln("serveUSAReport")

	sess, err := d.node.Session(lSeid)
	if err != nil {
		return errors.Wrap(err, "serveUSAReport")
	}

	return d.sendUSAReport(addr, sess, usars)
}

// sendUSAReport also accepts a just-cleaned Session retained by the retry caller.
func (d *Dispatcher) sendUSAReport(addr net.Addr, sess *Session, usars []report.USAReport) error {
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
					urrInfo.measurementMethod(), urrInfo.measurementInformation())...,
			))
	}

	err := d.transport.sendReqTo(&sessionReportRequest{SessionReportRequest: req, session: sess}, addr)
	return errors.Wrap(err, "serveUSAReport")
}

func measurementMethodFromBits(value uint8) report.MeasureMethod {
	return report.MeasureMethod{
		DURAT: value&0x01 != 0,
		VOLUM: value&0x02 != 0,
		EVENT: value&0x04 != 0,
	}
}

func measurementInformationFromBits(value uint64) report.MeasureInformation {
	return report.MeasureInformation{
		MBQE: value&0x01 != 0,
		INAM: value&0x02 != 0,
		RADI: value&0x04 != 0,
		ISTM: value&0x08 != 0,
		MNOP: value&0x10 != 0,
	}
}

func (info *URRInfo) measurementMethod() report.MeasureMethod {
	if info.Config.MeasureMethod == nil {
		return report.MeasureMethod{}
	}
	return measurementMethodFromBits(*info.Config.MeasureMethod)
}
func (info *URRInfo) measurementInformation() report.MeasureInformation {
	if info.Config.MeasureInformation == nil {
		return report.MeasureInformation{}
	}
	return measurementInformationFromBits(*info.Config.MeasureInformation)
}
