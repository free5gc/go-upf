package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	logger_util "github.com/free5gc/util/logger"
)

func TestHandleSessionReportResponseSEIDZeroCause(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 100, 200, 5), Port: 8805}
	newServerWithSession := func(remoteID uint64) (*PfcpServer, *Sess) {
		log := logger.PfcpLog.WithField(logger_util.FieldListenAddr, "upf.free5gc.org:8805")
		s := &PfcpServer{
			localNode: NewLocalNode("", time.Time{}, forwarder.Empty{}, log),
			log:       log,
		}
		association := s.localNode.EstablishAssociation("10.100.200.5", addr)
		return s, s.localNode.CreateSession(association, remoteID)
	}

	t.Run("keeps local session when cause is not session context not found", func(t *testing.T) {
		s, sess := newServerWithSession(0x1efce)
		req := message.NewSessionReportRequest(0, 0, sess.RemoteID, 1, 0)
		rsp := message.NewSessionReportResponse(
			0,
			0,
			0,
			1,
			0,
			ie.NewCause(ie.CauseRequestAccepted),
		)

		s.handleSessionReportResponse(rsp, addr, req)

		got, err := s.localNode.Session(sess.LocalID)
		assert.NoError(t, err)
		assert.Equal(t, sess.LocalID, got.LocalID)
	})

	t.Run("deletes local session when cause is session context not found", func(t *testing.T) {
		s, sess := newServerWithSession(0x1efce)
		req := message.NewSessionReportRequest(0, 0, sess.RemoteID, 1, 0)
		rsp := message.NewSessionReportResponse(
			0,
			0,
			0,
			1,
			0,
			ie.NewCause(ie.CauseSessionContextNotFound),
		)

		s.handleSessionReportResponse(rsp, addr, req)

		_, err := s.localNode.Session(sess.LocalID)
		assert.Error(t, err)
	})
}
