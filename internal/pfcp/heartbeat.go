package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (d *Dispatcher) handleHeartbeatRequest(req *message.HeartbeatRequest, addr net.Addr) {
	d.log.Infoln("handleHeartbeatRequest")

	rsp := message.NewHeartbeatResponse(
		req.Header.SequenceNumber,
		ie.NewRecoveryTimeStamp(d.node.RecoveryTime),
	)

	err := d.transport.sendRspTo(rsp, addr)
	if err != nil {
		d.log.Errorln(err)
		return
	}
}
