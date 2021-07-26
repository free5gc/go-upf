package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/m-asama/upf/factory"
	"github.com/m-asama/upf/logger"
)

func (s *PfcpServer) handleAssociationSetupRequest(req *message.AssociationSetupRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationSetupRequest")

	// TODO:
	// deleting the existing PFCP association and associated PFCP sessions,
	// if a PFCP association was already established for the Node ID
	// received in the request, regardless of the Recovery Timestamp
	// received in the request.

	cfg := factory.UpfConfig.Configuration

	var pfcpaddr string
	if addr, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		pfcpaddr = addr.IP.String()
	}

	// ASSOSI = 0
	// ASSONI = 1
	// TEIDRI(3) = 1
	// V6 = 0
	// V4 = 1
	var flags uint8
	flags |= uint8(1) << 5
	flags |= uint8(1) << 2
	flags |= uint8(1) << 0

	// tRange = 0
	var tRange uint8

	// TODO: only IPv4
	var v4 string
	var v6 string
	for _, e := range cfg.Gtpu {
		v4 = e.Addr
		break
	}

	// DNN
	var ni string
	for _, e := range cfg.DnnList {
		ni = e.Dnn
		break
	}

	// si = 0
	var si uint8

	rsp := message.NewAssociationSetupResponse(
		req.Header.SequenceNumber,
		ie.NewNodeID(pfcpaddr, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(s.recoveryTime),
		// TODO:
		// ie.NewUPFunctionFeatures(),
		ie.NewUserPlaneIPResourceInformation(
			flags,  // flags(spare, ASSOSI, ASSONI, TEIDRI(3), V6, V4
			tRange, // TEID Range
			v4,     // IPv4 Address
			v6,     // IPv6 Address
			ni,     // network instance
			si,     // source interface
		),
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

func (s *PfcpServer) handleAssociationUpdateRequest(msg *message.AssociationUpdateRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationUpdateRequest")
}

func (s *PfcpServer) handleAssociationReleaseRequest(msg *message.AssociationReleaseRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationReleaseRequest")
}
