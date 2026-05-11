package pfcp

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
	logger_util "github.com/free5gc/util/logger"
)

const (
	RECEIVE_CHANNEL_LEN       = 512
	REPORT_CHANNEL_LEN        = 128
	TRANS_TIMEOUT_CHANNEL_LEN = 64
	MONITORING_CHANNEL_LEN    = 32
	MAX_PFCP_MSG_LEN          = 65536
)

// monitoringReq is a request to add or remove a monitoring URR on a session.
// Requests are sent through monitoringCh to be processed by the PfcpServer
// main goroutine, ensuring thread-safe session state modifications.
type monitoringReq struct {
	add       bool
	remove    bool
	lSeid     uint64
	urrid     uint32
	repPeriod time.Duration
	respCh    chan error
}

type ReceivePacket struct {
	RemoteAddr net.Addr
	Buf        []byte
}

type TransType int

const (
	TX TransType = iota
	RX
)

type TransactionTimeout struct {
	TrType TransType
	TrID   string
}

type PfcpServer struct {
	cfg          *factory.Config
	listen       string
	nodeID       string
	rcvCh        chan ReceivePacket
	srCh         chan report.SessReport
	trToCh       chan TransactionTimeout
	monitoringCh chan monitoringReq
	conn         *net.UDPConn
	recoveryTime time.Time
	driver       forwarder.Driver
	lnode        LocalNode
	rnodes       map[string]*RemoteNode
	txTrans      map[string]*TxTransaction // key: RemoteAddr-Sequence
	rxTrans      map[string]*RxTransaction // key: RemoteAddr-Sequence
	txSeq        uint32
	log          *logrus.Entry
}

func NewPfcpServer(cfg *factory.Config, driver forwarder.Driver) *PfcpServer {
	listen := fmt.Sprintf("%s:%d", cfg.Pfcp.Addr, factory.UpfPfcpDefaultPort)
	return &PfcpServer{
		cfg:          cfg,
		listen:       listen,
		nodeID:       cfg.Pfcp.NodeID,
		rcvCh:        make(chan ReceivePacket, RECEIVE_CHANNEL_LEN),
		srCh:         make(chan report.SessReport, REPORT_CHANNEL_LEN),
		trToCh:       make(chan TransactionTimeout, TRANS_TIMEOUT_CHANNEL_LEN),
		monitoringCh: make(chan monitoringReq, MONITORING_CHANNEL_LEN),
		recoveryTime: time.Now(),
		driver:       driver,
		rnodes:       make(map[string]*RemoteNode),
		txTrans:      make(map[string]*TxTransaction),
		rxTrans:      make(map[string]*RxTransaction),
		log:          logger.PfcpLog.WithField(logger_util.FieldListenAddr, listen),
	}
}

// GetLocalNode returns the local PFCP node. Used by Nupf_EventExposure to enumerate sessions.
func (s *PfcpServer) GetLocalNode() *LocalNode {
	return &s.lnode
}

func (s *PfcpServer) main(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			s.log.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		s.log.Infoln("pfcp server stopped")
		s.stopTrTimers()
		close(s.rcvCh)
		close(s.srCh)
		close(s.trToCh)
		wg.Done()
	}()

	var err error
	laddr, err := net.ResolveUDPAddr("udp4", s.listen)
	if err != nil {
		s.log.Errorf("Resolve err: %+v", err)
		return
	}

	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		s.log.Errorf("Listen err: %+v", err)
		return
	}
	s.conn = conn

	wg.Add(1)
	go s.receiver(wg)

	for {
		select {
		case sr := <-s.srCh:
			s.log.Tracef("receive SessReport from srCh")
			s.ServeReport(&sr)
		case req := <-s.monitoringCh:
			s.log.Tracef("receive monitoring request from monitoringCh")
			var err error
			if req.add {
				err = s.doAddMonitoringURR(req.lSeid, req.urrid, req.repPeriod)
			} else if req.remove {
				err = s.doRemoveMonitoringURR(req.lSeid, req.urrid)
			} else {
				err = errors.New("invalid monitoring request")
			}
			req.respCh <- err
		case rcvPkt := <-s.rcvCh:
			s.log.Tracef("receive buf(len=%d) from rcvCh", len(rcvPkt.Buf))
			if len(rcvPkt.Buf) == 0 {
				// receiver closed
				return
			}

			msg, err := message.Parse(rcvPkt.Buf)
			if err != nil {
				s.log.Errorln(err)
				s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvPkt.Buf))
				continue
			}

			// This prevents malformed packets with inconsistent length fields
			if err = validatePfcpPacketLength(rcvPkt.Buf); err != nil {
				s.log.Warnf("Invalid PFCP packet from %s: %v", rcvPkt.RemoteAddr, err)
				s.log.Tracef("Rejected packet:\n%+v", hex.Dump(rcvPkt.Buf))
				continue
			}

			trID := fmt.Sprintf("%s-%d", rcvPkt.RemoteAddr, msg.Sequence())
			if isRequest(msg) {
				s.log.Tracef("receive req pkt from %s", trID)
				rx, ok := s.rxTrans[trID]
				if !ok {
					rx = NewRxTransaction(s, rcvPkt.RemoteAddr, msg.Sequence())
					s.rxTrans[trID] = rx
				}
				needDispatch, err1 := rx.recv(msg, ok)
				if err1 != nil {
					s.log.Warnf("rcvCh: %v", err1)
					continue
				} else if !needDispatch {
					s.log.Debugf("rcvCh: rxtr[%s] req no need to dispatch", trID)
					continue
				}
				err = s.reqDispacher(msg, rcvPkt.RemoteAddr)
				if err != nil {
					s.log.Errorln(err)
					s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvPkt.Buf))
				}
			} else if isResponse(msg) {
				s.log.Tracef("receive rsp pkt from %s", trID)
				tx, ok := s.txTrans[trID]
				if !ok {
					s.log.Debugf("rcvCh: No txtr[%s] found for rsp", trID)
					continue
				}
				req := tx.recv(msg)
				err = s.rspDispacher(msg, rcvPkt.RemoteAddr, req)
				if err != nil {
					s.log.Errorln(err)
					s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvPkt.Buf))
				}
			}
		case trTo := <-s.trToCh:
			s.log.Tracef("receive tr timeout (%v) from trToCh", trTo)
			if trTo.TrType == TX {
				tx, ok := s.txTrans[trTo.TrID]
				if !ok {
					s.log.Warnf("trToCh: txtr[%s] not found", trTo.TrID)
					continue
				}
				tx.handleTimeout()
			} else { // RX
				rx, ok := s.rxTrans[trTo.TrID]
				if !ok {
					s.log.Warnf("trToCh: rxtr[%s] not found", trTo.TrID)
					continue
				}
				rx.handleTimeout()
			}
		}
	}
}

func (s *PfcpServer) receiver(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			s.log.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		s.log.Infoln("pfcp reciver stopped")
		wg.Done()
	}()

	buf := make([]byte, MAX_PFCP_MSG_LEN)
	for {
		s.log.Tracef("receiver starts to read...")
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			s.log.Errorf("%+v", err)
			s.rcvCh <- ReceivePacket{}
			break
		}

		s.log.Tracef("receiver reads message(len=%d)", n)
		msgBuf := make([]byte, n)
		copy(msgBuf, buf)
		s.rcvCh <- ReceivePacket{
			RemoteAddr: addr,
			Buf:        msgBuf,
		}
	}
}

func (s *PfcpServer) Start(wg *sync.WaitGroup) {
	s.log.Infoln("starting pfcp server")
	wg.Add(1)
	go s.main(wg)
	s.log.Infoln("pfcp server started")
}

func (s *PfcpServer) Stop() {
	s.log.Infoln("Stopping pfcp server")
	if s.conn != nil {
		err := s.conn.Close()
		if err != nil {
			s.log.Errorf("Stop pfcp server err: %+v", err)
		}
	}
}

func (s *PfcpServer) NewNode(id string, addr net.Addr, driver forwarder.Driver) *RemoteNode {
	n := NewRemoteNode(
		id,
		addr,
		&s.lnode,
		driver,
		s.log.WithField(logger_util.FieldControlPlaneNodeID, id),
	)
	n.log.Infoln("New node")
	return n
}

func (s *PfcpServer) UpdateNodeID(n *RemoteNode, newId string) {
	s.log.Infof("Update nodeId %q to %q", n.ID, newId)
	delete(s.rnodes, n.ID)
	n.ID = newId
	n.log = s.log.WithField(logger_util.FieldControlPlaneNodeID, newId)
	s.rnodes[newId] = n
}

func (s *PfcpServer) NotifySessReport(sr report.SessReport) {
	s.srCh <- sr
}

func (s *PfcpServer) NotifyTransTimeout(trType TransType, trID string) {
	s.trToCh <- TransactionTimeout{TrType: trType, TrID: trID}
}

func (s *PfcpServer) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	sess, err := s.lnode.Sess(seid)
	if err != nil {
		s.log.Errorln(err)
		return nil, false
	}
	return sess.Pop(pdrid)
}

func (s *PfcpServer) sendReqTo(msg message.Message, addr net.Addr) error {
	if !isRequest(msg) {
		return errors.Errorf("sendReqTo: invalid req type(%d)", msg.MessageType())
	}

	txtr := NewTxTransaction(s, addr, s.txSeq)
	s.txSeq++
	s.txTrans[txtr.id] = txtr

	return txtr.send(msg)
}

func (s *PfcpServer) sendRspTo(msg message.Message, addr net.Addr) error {
	if !isResponse(msg) {
		return errors.Errorf("sendRspTo: invalid rsp type(%d)", msg.MessageType())
	}

	// find transaction
	trID := fmt.Sprintf("%s-%d", addr, msg.Sequence())
	rxtr, ok := s.rxTrans[trID]
	if !ok {
		return errors.Errorf("sendRspTo: rxtr(%s) not found", trID)
	}

	return rxtr.send(msg)
}

func (s *PfcpServer) stopTrTimers() {
	for _, tx := range s.txTrans {
		if tx.timer == nil {
			continue
		}
		tx.timer.Stop()
		tx.timer = nil
	}
	for _, rx := range s.rxTrans {
		if rx.timer == nil {
			continue
		}
		rx.timer.Stop()
		rx.timer = nil
	}
}

func isRequest(msg message.Message) bool {
	switch msg.MessageType() {
	case message.MsgTypeHeartbeatRequest:
		return true
	case message.MsgTypePFDManagementRequest:
		return true
	case message.MsgTypeAssociationSetupRequest:
		return true
	case message.MsgTypeAssociationUpdateRequest:
		return true
	case message.MsgTypeAssociationReleaseRequest:
		return true
	case message.MsgTypeNodeReportRequest:
		return true
	case message.MsgTypeSessionSetDeletionRequest:
		return true
	case message.MsgTypeSessionEstablishmentRequest:
		return true
	case message.MsgTypeSessionModificationRequest:
		return true
	case message.MsgTypeSessionDeletionRequest:
		return true
	case message.MsgTypeSessionReportRequest:
		return true
	default:
	}
	return false
}

func isResponse(msg message.Message) bool {
	switch msg.MessageType() {
	case message.MsgTypeHeartbeatResponse:
		return true
	case message.MsgTypePFDManagementResponse:
		return true
	case message.MsgTypeAssociationSetupResponse:
		return true
	case message.MsgTypeAssociationUpdateResponse:
		return true
	case message.MsgTypeAssociationReleaseResponse:
		return true
	case message.MsgTypeNodeReportResponse:
		return true
	case message.MsgTypeSessionSetDeletionResponse:
		return true
	case message.MsgTypeSessionEstablishmentResponse:
		return true
	case message.MsgTypeSessionModificationResponse:
		return true
	case message.MsgTypeSessionDeletionResponse:
		return true
	case message.MsgTypeSessionReportResponse:
		return true
	default:
	}
	return false
}

func setReqSeq(msgtmp message.Message, seq uint32) {
	switch msg := msgtmp.(type) {
	case *message.HeartbeatRequest:
		msg.SetSequenceNumber(seq)
	case *message.PFDManagementRequest:
		msg.SetSequenceNumber(seq)
	case *message.AssociationSetupRequest:
		msg.SetSequenceNumber(seq)
	case *message.AssociationUpdateRequest:
		msg.SetSequenceNumber(seq)
	case *message.AssociationReleaseRequest:
		msg.SetSequenceNumber(seq)
	case *message.NodeReportRequest:
		msg.SetSequenceNumber(seq)
	case *message.SessionSetDeletionRequest:
		msg.SetSequenceNumber(seq)
	case *message.SessionEstablishmentRequest:
		msg.SetSequenceNumber(seq)
	case *message.SessionModificationRequest:
		msg.SetSequenceNumber(seq)
	case *message.SessionDeletionRequest:
		msg.SetSequenceNumber(seq)
	case *message.SessionReportRequest:
		msg.SetSequenceNumber(seq)
	default:
	}
}

func validatePfcpPacketLength(buf []byte) error {
	// Minimum PFCP message: 8 bytes (header without SEID)
	if len(buf) < 8 {
		return fmt.Errorf("packet too short: %d bytes (minimum 8 bytes required)", len(buf))
	}

	// Read Message Length field (bytes 2-3, big-endian)
	declaredLen := uint16(buf[2])<<8 | uint16(buf[3])

	// Total = 4 bytes (fixed header) + declared message length
	expectedTotalLen := int(declaredLen) + 4

	// Check if declared length matches actual received length
	actualLen := len(buf)
	if actualLen != expectedTotalLen {
		return fmt.Errorf("message length mismatch: header declares %d bytes total, but received %d bytes",
			expectedTotalLen, actualLen)
	}

	return nil
}

// AddMonitoringURR asynchronously creates a monitoring URR on the specified session.
// Safe to call from any goroutine; executes in the PfcpServer main loop.
func (s *PfcpServer) AddMonitoringURR(lSeid uint64, urrid uint32, repPeriod time.Duration) error {
	respCh := make(chan error, 1)
	s.monitoringCh <- monitoringReq{add: true, lSeid: lSeid, urrid: urrid, repPeriod: repPeriod, respCh: respCh}
	return <-respCh
}

// RemoveMonitoringURR asynchronously removes a monitoring URR from the specified session.
// Safe to call from any goroutine; executes in the PfcpServer main loop.
func (s *PfcpServer) RemoveMonitoringURR(lSeid uint64, urrid uint32) error {
	respCh := make(chan error, 1)
	s.monitoringCh <- monitoringReq{remove: true, lSeid: lSeid, urrid: urrid, respCh: respCh}
	return <-respCh
}

// doAddMonitoringURR creates a URR and links it to all PDRs of the session.
// Must run in the PfcpServer main goroutine.
func (s *PfcpServer) doAddMonitoringURR(lSeid uint64, urrid uint32, repPeriod time.Duration) error {
	sess, err := s.lnode.Sess(lSeid)
	if err != nil {
		return err
	}

	// Build CreateURR IE: VOLUM measurement, PERIO trigger, given period.
	// ReportingTriggers IE requires at least 2 octets (per go-pfcp and TS 29.244).
	// Octet 5: PERIO=bit0=0x01; Octet 6: 0x00 (no additional triggers).
	urrIE := ie.NewCreateURR(
		ie.NewURRID(urrid),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM=1
		ie.NewReportingTriggers(0x01, 0x00), // PERIO (2-octet form required)
		ie.NewMeasurementPeriod(repPeriod),
	)

	urrPlan, err := sess.ValidateCreateURR(urrIE)
	if err != nil {
		return errors.Wrap(err, "ValidateCreateURR")
	}

	plan := forwarder.NewModificationPlan(lSeid)
	plan.CreateURRs = []*forwarder.URRPlan{urrPlan}

	// Add URRID to each PDR that has a stored IE so we can reconstruct UpdatePDR.
	for pdrid, pdrInfo := range sess.PDRIDs {
		if pdrInfo.LastIE == nil {
			continue
		}
		combined := make(map[uint32]struct{}, len(pdrInfo.RelatedURRIDs)+1)
		for id := range pdrInfo.RelatedURRIDs {
			combined[id] = struct{}{}
		}
		combined[urrid] = struct{}{}

		updateIE, buildErr := buildUpdatePDRIEForURRSet(pdrInfo.LastIE, pdrid, combined)
		if buildErr != nil {
			s.log.Warnf("buildUpdatePDRIEForURRSet pdr[%d]: %v", pdrid, buildErr)
			continue
		}
		p, buildErr := sess.ValidateUpdatePDR(updateIE, plan)
		if buildErr != nil {
			s.log.Warnf("ValidateUpdatePDR pdr[%d]: %v", pdrid, buildErr)
			continue
		}
		plan.UpdatePDRs = append(plan.UpdatePDRs, p)
	}

	_, err = s.driver.ExecuteModificationPlan(plan)
	if err != nil {
		return errors.Wrap(err, "ExecuteModificationPlan")
	}

	sess.ApplyCreateURR(urrPlan)
	for _, p := range plan.UpdatePDRs {
		sess.ApplyUpdatePDR(p)
	}
	return nil
}

// doRemoveMonitoringURR removes a monitoring URR from the session and unlinks it from PDRs.
// Must run in the PfcpServer main goroutine.
func (s *PfcpServer) doRemoveMonitoringURR(lSeid uint64, urrid uint32) error {
	sess, err := s.lnode.Sess(lSeid)
	if err != nil {
		return err
	}

	if _, exists := sess.URRIDs[urrid]; !exists {
		return nil // Already removed
	}

	plan := forwarder.NewModificationPlan(lSeid)
	removeURRIE := ie.NewRemoveURR(ie.NewURRID(urrid))
	urrPlan, err := sess.ValidateRemoveURR(removeURRIE, plan)
	if err != nil {
		return errors.Wrap(err, "ValidateRemoveURR")
	}
	plan.RemoveURRs = append(plan.RemoveURRs, urrPlan)

	for pdrid, pdrInfo := range sess.PDRIDs {
		if _, linked := pdrInfo.RelatedURRIDs[urrid]; !linked {
			continue
		}
		if pdrInfo.LastIE == nil {
			continue
		}
		reduced := make(map[uint32]struct{}, len(pdrInfo.RelatedURRIDs))
		for id := range pdrInfo.RelatedURRIDs {
			if id != urrid {
				reduced[id] = struct{}{}
			}
		}
		updateIE, buildErr := buildUpdatePDRIEForURRSet(pdrInfo.LastIE, pdrid, reduced)
		if buildErr != nil {
			s.log.Warnf("buildUpdatePDRIEForURRSet pdr[%d]: %v", pdrid, buildErr)
			continue
		}
		p, buildErr := sess.ValidateUpdatePDR(updateIE, plan)
		if buildErr != nil {
			s.log.Warnf("ValidateUpdatePDR pdr[%d]: %v", pdrid, buildErr)
			continue
		}
		plan.UpdatePDRs = append(plan.UpdatePDRs, p)
	}

	_, err = s.driver.ExecuteModificationPlan(plan)
	if err != nil {
		return errors.Wrap(err, "ExecuteModificationPlan")
	}

	sess.ApplyRemoveURR(urrPlan)
	for _, p := range plan.UpdatePDRs {
		sess.ApplyUpdatePDR(p)
	}
	return nil
}

// buildUpdatePDRIEForURRSet reconstructs an UpdatePDR IE from a stored CreatePDR/UpdatePDR IE,
// replacing the URRID sub-IEs with the given set. This is needed because gtp5g kernel driver
// uses NLM_F_REPLACE which requires all PDR attributes to be resent on update.
func buildUpdatePDRIEForURRSet(lastIE *ie.IE, pdrid uint16, urrIDs map[uint32]struct{}) (*ie.IE, error) {
	var subIEs []*ie.IE
	var err error
	switch lastIE.Type {
	case ie.CreatePDR:
		subIEs, err = lastIE.CreatePDR()
	case ie.UpdatePDR:
		subIEs, err = lastIE.UpdatePDR()
	default:
		return nil, fmt.Errorf("unknown PDR IE type %d", lastIE.Type)
	}
	if err != nil {
		return nil, err
	}

	out := make([]*ie.IE, 0, len(subIEs)+len(urrIDs))
	pdridFound := false
	for _, sub := range subIEs {
		if sub.Type == ie.URRID {
			continue // Strip existing URRID IEs; we will re-add below
		}
		if sub.Type == ie.PDRID {
			pdridFound = true
			out = append(out, ie.NewPDRID(pdrid))
		} else {
			out = append(out, sub)
		}
	}
	if !pdridFound {
		out = append(out, ie.NewPDRID(pdrid))
	}
	for id := range urrIDs {
		out = append(out, ie.NewURRID(id))
	}
	return ie.NewUpdatePDR(out...), nil
}
