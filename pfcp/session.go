package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/m-asama/upf/logger"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(req *message.SessionEstablishmentRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleSessionEstablishmentRequest")

	for _, i := range req.CreateFAR {
		err := s.driver.CreateFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreateQER {
		err := s.driver.CreateQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreatePDR {
		err := s.driver.CreatePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	var seid uint64
	var v4 net.IP
	var v6 net.IP

	// TODO:
	// allocate a session
	seid = 1

	var pfcpaddr string
	if addr, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		v4 = addr.IP
		pfcpaddr = v4.String()
	}

	rsp := message.NewSessionEstablishmentResponse(
		0,    // mp
		0,    // fo
		seid, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewNodeID(pfcpaddr, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(seid, v4, v6),
	)

	b, err := rsp.Marshal()
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}
}

func (s *PfcpServer) handleSessionModificationRequest(req *message.SessionModificationRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleSessionModificationRequest")

	for _, i := range req.CreateFAR {
		err := s.driver.CreateFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreateQER {
		err := s.driver.CreateQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreatePDR {
		err := s.driver.CreatePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.RemoveFAR {
		err := s.driver.RemoveFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.RemoveQER {
		err := s.driver.RemoveQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.RemovePDR {
		err := s.driver.RemovePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.UpdateFAR {
		err := s.driver.UpdateFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.UpdateQER {
		err := s.driver.UpdateQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.UpdatePDR {
		err := s.driver.UpdatePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	rsp := message.NewSessionModificationResponse(
		0,               // mp
		0,               // fo
		req.Header.SEID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
	)

	b, err := rsp.Marshal()
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}
}

func (s *PfcpServer) handleSessionDeletionRequest(msg *message.SessionDeletionRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleSessionDeletionRequest")
}
