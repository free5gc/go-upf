package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (h *MessageHandler) handleHeartbeatRequest(req *message.HeartbeatRequest, addr net.Addr) {
	h.log.Infoln("handleHeartbeatRequest")

	rsp := message.NewHeartbeatResponse(
		req.Header.SequenceNumber,
		ie.NewRecoveryTimeStamp(h.node.RecoveryTime),
	)

	err := h.transport.sendRspTo(rsp, addr)
	if err != nil {
		h.log.Errorln(err)
		return
	}
}
