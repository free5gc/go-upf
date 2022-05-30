package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
)

type Transaction struct {
	raddr string
	txSeq uint32
	tx    map[uint32]*Element // key: seq
	rx    map[uint32]*Element // key: seq
	log   *logrus.Entry
}

type Element struct {
	msgBuf []byte
	seq    uint32
}

func NewTransaction(raddr string, log *logrus.Entry) *Transaction {
	return &Transaction{
		raddr: raddr,
		txSeq: 1,
		tx:    make(map[uint32]*Element),
		rx:    make(map[uint32]*Element),
		log:   log.WithField(logger.FieldTransction, fmt.Sprintf("Tr:%s", raddr)),
	}
}

func (t *Transaction) txSend(conn *net.UDPConn, msg message.Message, addr net.Addr) error {
	e := &Element{
		seq: t.txSeq,
	}
	t.tx[t.txSeq] = e
	// msg.SetSequence(t.txSeq)
	t.txSeq++
	t.log.Debugf("tx[%d] send req", e.seq)

	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}
	e.msgBuf = b

	_, err = conn.WriteTo(b, addr)
	if err != nil {
		return err
	}

	// Start tx retransmission timer

	return nil
}

func (t *Transaction) txRecv(conn *net.UDPConn, msg message.Message, addr net.Addr) error {
	_, ok := t.tx[msg.Sequence()]
	if !ok {
		return errors.Errorf("No tx found for msg seq(%d)", msg.Sequence())
	}
	t.log.Debugf("tx[%d] recv rsp", msg.Sequence())

	// Stop tx retransmission timer

	delete(t.tx, msg.Sequence())
	return nil
}

func (t *Transaction) rxSend(conn *net.UDPConn, msg message.Message, addr net.Addr) error {
	e, ok := t.rx[msg.Sequence()]
	if !ok {
		return errors.Errorf("No rx found for msg seq(%d)", msg.Sequence())
	}
	t.log.Debugf("rx[%d] send rsp", msg.Sequence())

	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}
	e.msgBuf = b

	_, err = conn.WriteTo(b, addr)
	if err != nil {
		return err
	}

	// Start rx timer to delete rx

	return nil
}

// True - need to handle this msg
// False - msg already handled
func (t *Transaction) rxRecv(conn *net.UDPConn, msg message.Message, addr net.Addr) (bool, error) {
	e, ok := t.rx[msg.Sequence()]
	if !ok {
		e = &Element{
			seq: msg.Sequence(),
		}
		t.rx[e.seq] = e
		t.log.Debugf("rx[%d] recv req", msg.Sequence())
		return true, nil
	}

	if len(e.msgBuf) == 0 {
		return false, errors.Errorf("No rsp can be retransmitted")
	}

	t.log.Debugf("rx[%d] recv req: retransmit rsp", msg.Sequence())
	_, err := conn.WriteTo(e.msgBuf, addr)
	if err != nil {
		return false, errors.Wrap(err, "rxRecieve")
	}
	return false, nil
}
