package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/m-asama/upf/logger"
)

func (s *PfcpServer) handleAssociationSetupRequest(msg *message.AssociationSetupRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationSetupRequest")
}

func (s *PfcpServer) handleAssociationUpdateRequest(msg *message.AssociationUpdateRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationUpdateRequest")
}

func (s *PfcpServer) handleAssociationReleaseRequest(msg *message.AssociationReleaseRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationReleaseRequest")
}
