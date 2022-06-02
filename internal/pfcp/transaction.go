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

type TxTransaction struct {
	server         *PfcpServer
	raddr          net.Addr
	seq            uint32
	id             string
	retransTimeout time.Duration
	maxRetrans     uint8
	msgBuf         []byte
	timer          *time.Timer
	retransCount   uint8
	rspCh          chan<- Response
	log            *logrus.Entry
}

type RxTransaction struct {
	server  *PfcpServer
	raddr   net.Addr
	seq     uint32
	id      string
	timeout time.Duration
	msgBuf  []byte
	timer   *time.Timer
	log     *logrus.Entry
}

func NewTxTransaction(
	server *PfcpServer,
	raddr net.Addr,
	seq uint32,
	rspCh chan<- Response,
) *TxTransaction {
	return &TxTransaction{
		server:         server,
		raddr:          raddr,
		seq:            seq,
		id:             fmt.Sprintf("%s-%d", raddr, seq),
		retransTimeout: server.cfg.Pfcp.RetransTimeout,
		maxRetrans:     server.cfg.Pfcp.MaxRetrans,
		rspCh:          rspCh,
		log:            server.log.WithField(logger.FieldTransction, fmt.Sprintf("TxTr:%s(%d)", raddr, seq)),
	}
}

func (tx *TxTransaction) send(msg message.Message) error {
	tx.log.Debugf("send req")

	setReqSeq(msg, tx.seq)
	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}

	// Start tx retransmission timer
	tx.msgBuf = b
	tx.timer = tx.startTimer()

	_, err = tx.server.conn.WriteTo(b, tx.raddr)
	if err != nil {
		return err
	}

	return nil
}

func (tx *TxTransaction) recv(msg message.Message) {
	tx.log.Debugf("recv rsp, delete txtr")

	// notify sender rsp received
	if tx.rspCh != nil {
		tx.log.Debugf("notify app rsp")
		tx.rspCh <- Response{
			RemoteAddr: tx.raddr,
			Msg:        msg,
		}
	}

	// Stop tx retransmission timer
	tx.timer.Stop()
	tx.timer = nil

	delete(tx.server.txTrans, tx.id)
}

func (tx *TxTransaction) handleTimeout() {
	if tx.retransCount < tx.maxRetrans {
		// Start tx retransmission timer
		tx.retransCount++
		tx.log.Debugf("timeout, retransCount(%d)", tx.retransCount)
		_, err := tx.server.conn.WriteTo(tx.msgBuf, tx.raddr)
		if err != nil {
			tx.log.Errorf("retransmit[%d] error: %v", tx.retransCount, err)
		}
		tx.timer = tx.startTimer()
	} else {
		tx.log.Debugf("max retransmission reached - delete txtr")
		delete(tx.server.txTrans, tx.id)
		if tx.rspCh != nil {
			tx.log.Debugf("notify app timeout")
			tx.rspCh <- Response{
				RemoteAddr: tx.raddr,
				Msg:        nil,
			}
		}
	}
}

func (tx *TxTransaction) startTimer() *time.Timer {
	tx.log.Debugf("start timer(%s)", tx.retransTimeout)
	t := time.AfterFunc(
		tx.retransTimeout,
		func() {
			tx.server.NotifyTransTimeout(TX, tx.id)
		},
	)
	return t
}

func NewRxTransaction(
	server *PfcpServer,
	raddr net.Addr,
	seq uint32,
) *RxTransaction {
	return &RxTransaction{
		server:  server,
		raddr:   raddr,
		seq:     seq,
		id:      fmt.Sprintf("%s-%d", raddr, seq),
		timeout: server.cfg.Pfcp.RetransTimeout * time.Duration(server.cfg.Pfcp.MaxRetrans+1),
		log:     server.log.WithField(logger.FieldTransction, fmt.Sprintf("RxTr:%s(%d)", raddr, seq)),
	}
}

func (rx *RxTransaction) send(msg message.Message) error {
	rx.log.Debugf("send rsp")

	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}

	// Start rx timer to delete rx
	rx.msgBuf = b
	rx.timer = rx.startTimer()

	_, err = rx.server.conn.WriteTo(b, rx.raddr)
	if err != nil {
		return err
	}

	return nil
}

// True  - need to handle this req
// False - req already handled
func (rx *RxTransaction) recv(msg message.Message) (bool, error) {
	rx.log.Debugf("recv req")
	if len(rx.msgBuf) == 0 {
		return true, nil
	}

	rx.log.Debugf("recv req: retransmit rsp")
	_, err := rx.server.conn.WriteTo(rx.msgBuf, rx.raddr)
	if err != nil {
		return false, errors.Wrapf(err, "rxtr[%s] recv", rx.id)
	}
	return false, nil
}

func (rx *RxTransaction) handleTimeout() {
	rx.log.Debugf("timeout, delete rxtr")
	delete(rx.server.rxTrans, rx.id)
}

func (rx *RxTransaction) startTimer() *time.Timer {
	rx.log.Debugf("start timer(%s)", rx.timeout)
	t := time.AfterFunc(
		rx.timeout,
		func() {
			rx.server.NotifyTransTimeout(RX, rx.id)
		},
	)
	return t
}
