package pfcp

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
)

type Transaction struct {
	server         *PfcpServer
	raddr          net.Addr
	txSeq          uint32
	retransTimeout time.Duration
	maxRetrans     uint8
	tx             map[uint32]*Element // key: seq
	rx             map[uint32]*Element // key: seq
	log            *logrus.Entry
}

type Element struct {
	msgBuf       []byte
	seq          uint32
	timer        *time.Timer
	retransCount uint8
	rspCh        chan<- Response
}

func NewTransaction(server *PfcpServer, raddr net.Addr) *Transaction {
	return &Transaction{
		server:         server,
		raddr:          raddr,
		txSeq:          0,
		retransTimeout: server.cfg.Pfcp.RetransTimeout,
		maxRetrans:     server.cfg.Pfcp.MaxRetrans,
		tx:             make(map[uint32]*Element),
		rx:             make(map[uint32]*Element),
		log:            server.log.WithField(logger.FieldTransction, fmt.Sprintf("Tr:%s", raddr)),
	}
}

func (tr *Transaction) txSend(msg message.Message, rspCh chan<- Response) error {
	e := &Element{
		seq:   tr.txSeq,
		rspCh: rspCh,
	}
	tr.tx[tr.txSeq] = e
	// msg.SetSequenceNumber(t.txSeq)
	tr.txSeq++
	tr.log.Debugf("tx[%d] send req", e.seq)

	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}

	// Start tx retransmission timer
	e.msgBuf = b
	e.timer = tr.startTxTimer(e.seq)

	_, err = tr.server.conn.WriteTo(b, tr.raddr)
	if err != nil {
		return err
	}

	return nil
}

func (tr *Transaction) txRecv(msg message.Message) error {
	e, ok := tr.tx[msg.Sequence()]
	if !ok {
		return errors.Errorf("No tx found for msg seq(%d)", msg.Sequence())
	}
	tr.log.Debugf("tx[%d] recv rsp, delete tx", msg.Sequence())

	// notify sender rsp received
	if e.rspCh != nil {
		tr.log.Debugf("tx[%d] notify app rsp", msg.Sequence())
		e.rspCh <- Response{
			RemoteAddr: tr.raddr,
			Msg:        msg,
		}
	}

	// Stop tx retransmission timer
	e.timer.Stop()
	e.timer = nil

	delete(tr.tx, msg.Sequence())
	return nil
}

func (tr *Transaction) rxSend(msg message.Message) error {
	e, ok := tr.rx[msg.Sequence()]
	if !ok {
		return errors.Errorf("No rx found for msg seq(%d)", msg.Sequence())
	}
	tr.log.Debugf("rx[%d] send rsp", msg.Sequence())

	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}

	// Start rx timer to delete rx
	e.msgBuf = b
	e.timer = tr.startRxTimer(e.seq)

	_, err = tr.server.conn.WriteTo(b, tr.raddr)
	if err != nil {
		return err
	}

	return nil
}

// True - need to handle this req
// False - req already handled
func (tr *Transaction) rxRecv(msg message.Message) (bool, error) {
	e, ok := tr.rx[msg.Sequence()]
	if !ok {
		e = &Element{
			seq: msg.Sequence(),
		}
		tr.rx[e.seq] = e
		tr.log.Debugf("rx[%d] recv req", msg.Sequence())
		return true, nil
	}

	if len(e.msgBuf) == 0 {
		return false, errors.Errorf("No rsp can be retransmitted")
	}

	tr.log.Debugf("rx[%d] recv req: retransmit rsp", msg.Sequence())
	_, err := tr.server.conn.WriteTo(e.msgBuf, tr.raddr)
	if err != nil {
		return false, errors.Wrap(err, "rxRecieve")
	}
	return false, nil
}

func (tr *Transaction) handleTxTimeout(seq uint32) {
	e, ok := tr.tx[seq]
	if !ok {
		tr.log.Debugf("tx[%d] not found, ignore tx timeout", seq)
		return
	}

	// Start tx retransmission timer
	if e.retransCount < tr.maxRetrans {
		e.retransCount++
		tr.log.Debugf("tx[%d] timeout, retransCount(%d)", seq, e.retransCount)
		_, err := tr.server.conn.WriteTo(e.msgBuf, tr.raddr)
		if err != nil {
			tr.log.Errorf("tx[%d] retransmit[%d] error: %v", seq, e.retransCount, err)
		}
		e.timer = tr.startTxTimer(e.seq)
	} else {
		tr.log.Debugf("tx[%d] max retransmission reached", seq)
		delete(tr.tx, seq)
		if e.rspCh != nil {
			tr.log.Debugf("tx[%d] notify app timeout", seq)
			e.rspCh <- Response{
				RemoteAddr: tr.raddr,
				Msg:        nil,
			}
		}
	}
}

func (tr *Transaction) handleRxTimeout(seq uint32) {
	_, ok := tr.rx[seq]
	if !ok {
		tr.log.Debugf("rx[%d] not found, ignore rx timeout", seq)
		return
	}
	tr.log.Debugf("rx[%d] timeout, delete it", seq)
	delete(tr.rx, seq)
}

func (tr *Transaction) startTxTimer(seq uint32) *time.Timer {
	tr.log.Debugf("tx[%d] start timer(%s)", seq, tr.retransTimeout.String())
	t := time.AfterFunc(
		tr.retransTimeout,
		func() {
			tr.server.NotifyTransTimeout(TX, tr.raddr.String(), seq)
		},
	)
	return t
}

func (tr *Transaction) startRxTimer(seq uint32) *time.Timer {
	rxTo := tr.retransTimeout * time.Duration(tr.maxRetrans+1)
	tr.log.Debugf("rx[%d] start timer(%s)", seq, rxTo.String())
	t := time.AfterFunc(
		rxTo,
		func() {
			tr.server.NotifyTransTimeout(RX, tr.raddr.String(), seq)
		},
	)
	return t
}

func (tr *Transaction) stopAllTimers() {
	for _, e := range tr.tx {
		if e.timer == nil {
			continue
		}
		e.timer.Stop()
		e.timer = nil
	}
	for _, e := range tr.rx {
		if e.timer == nil {
			continue
		}
		e.timer.Stop()
		e.timer = nil
	}
}
