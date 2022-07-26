package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
)

const (
	BUFFQ_LEN = 512
)

type Sess struct {
	rnode    *RemoteNode
	LocalID  uint64
	RemoteID uint64
	PDRIDs   map[uint16]struct{}
	FARIDs   map[uint32]struct{}
	QERIDs   map[uint32]struct{}
	URRIDs   map[uint32]struct{}
	BARIDs   map[uint8]struct{}
	q        map[uint16]chan []byte // key: PDR_ID
	qlen     int
	log      *logrus.Entry
}

func (s *Sess) Close() {
	for id := range s.FARIDs {
		i := ie.NewRemoveFAR(ie.NewFARID(id))
		err := s.RemoveFAR(i)
		if err != nil {
			s.log.Errorf("Remove FAR err: %+v", err)
		}
	}
	for id := range s.QERIDs {
		i := ie.NewRemoveQER(ie.NewQERID(id))
		err := s.RemoveQER(i)
		if err != nil {
			s.log.Errorf("Remove QER err: %+v", err)
		}
	}
	for id := range s.URRIDs {
		i := ie.NewRemoveURR(ie.NewURRID(id))
		err := s.RemoveURR(i)
		if err != nil {
			s.log.Errorf("Remove URR err: %+v", err)
		}
	}
	for id := range s.BARIDs {
		i := ie.NewRemoveBAR(ie.NewBARID(id))
		err := s.RemoveBAR(i)
		if err != nil {
			s.log.Errorf("Remove BAR err: %+v", err)
		}
	}
	for id := range s.PDRIDs {
		i := ie.NewRemovePDR(ie.NewPDRID(id))
		err := s.RemovePDR(i)
		if err != nil {
			s.log.Errorf("remove PDR err: %+v", err)
		}
	}
	for _, q := range s.q {
		close(q)
	}
}

func (s *Sess) CreatePDR(req *ie.IE) error {
	err := s.rnode.driver.CreatePDR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.PDRID()
	if err != nil {
		return err
	}
	s.PDRIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdatePDR(req *ie.IE) error {
	return s.rnode.driver.UpdatePDR(s.LocalID, req)
}

func (s *Sess) RemovePDR(req *ie.IE) error {
	err := s.rnode.driver.RemovePDR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.PDRID()
	if err != nil {
		return err
	}
	delete(s.PDRIDs, id)
	return nil
}

func (s *Sess) CreateFAR(req *ie.IE) error {
	err := s.rnode.driver.CreateFAR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.FARID()
	if err != nil {
		return err
	}
	s.FARIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateFAR(req *ie.IE) error {
	return s.rnode.driver.UpdateFAR(s.LocalID, req)
}

func (s *Sess) RemoveFAR(req *ie.IE) error {
	err := s.rnode.driver.RemoveFAR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.FARID()
	if err != nil {
		return err
	}
	delete(s.FARIDs, id)
	return nil
}

func (s *Sess) CreateQER(req *ie.IE) error {
	err := s.rnode.driver.CreateQER(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.QERID()
	if err != nil {
		return err
	}
	s.QERIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateQER(req *ie.IE) error {
	return s.rnode.driver.UpdateQER(s.LocalID, req)
}

func (s *Sess) RemoveQER(req *ie.IE) error {
	err := s.rnode.driver.RemoveQER(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.QERID()
	if err != nil {
		return err
	}
	delete(s.QERIDs, id)
	return nil
}

func (s *Sess) CreateURR(req *ie.IE) error {
	err := s.rnode.driver.CreateURR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.URRID()
	if err != nil {
		return err
	}
	s.URRIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateURR(req *ie.IE) error {
	return s.rnode.driver.UpdateURR(s.LocalID, req)
}

func (s *Sess) RemoveURR(req *ie.IE) error {
	err := s.rnode.driver.RemoveURR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.URRID()
	if err != nil {
		return err
	}
	delete(s.URRIDs, id)
	return nil
}

func (s *Sess) CreateBAR(req *ie.IE) error {
	err := s.rnode.driver.CreateBAR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.BARID()
	if err != nil {
		return err
	}
	s.BARIDs[id] = struct{}{}
	return nil
}

func (s *Sess) UpdateBAR(req *ie.IE) error {
	return s.rnode.driver.UpdateBAR(s.LocalID, req)
}

func (s *Sess) RemoveBAR(req *ie.IE) error {
	err := s.rnode.driver.RemoveBAR(s.LocalID, req)
	if err != nil {
		return err
	}

	id, err := req.BARID()
	if err != nil {
		return err
	}
	delete(s.BARIDs, id)
	return nil
}

func (s *Sess) Push(pdrid uint16, p []byte) {
	pkt := make([]byte, len(p))
	copy(pkt, p)
	q, ok := s.q[pdrid]
	if !ok {
		s.q[pdrid] = make(chan []byte, s.qlen)
		q = s.q[pdrid]
	}

	select {
	case q <- pkt:
		s.log.Debugf("Push bufPkt to q[%d](len:%d)", pdrid, len(q))
	default:
		s.log.Debugf("q[%d](len:%d) is full, drop it", pdrid, len(q))
	}
}

func (s *Sess) Len(pdrid uint16) int {
	q, ok := s.q[pdrid]
	if !ok {
		return 0
	}
	return len(q)
}

func (s *Sess) Pop(pdrid uint16) ([]byte, bool) {
	q, ok := s.q[pdrid]
	if !ok {
		return nil, ok
	}
	select {
	case pkt := <-q:
		s.log.Debugf("Pop bufPkt from q[%d](len:%d)", pdrid, len(q))
		return pkt, true
	default:
		return nil, false
	}
}

type RemoteNode struct {
	ID     string
	addr   net.Addr
	local  *LocalNode
	sess   map[uint64]struct{} // key: Local SEID
	driver forwarder.Driver
	log    *logrus.Entry
}

func NewRemoteNode(
	id string,
	addr net.Addr,
	local *LocalNode,
	driver forwarder.Driver,
	log *logrus.Entry,
) *RemoteNode {
	n := new(RemoteNode)
	n.ID = id
	n.addr = addr
	n.local = local
	n.sess = make(map[uint64]struct{})
	n.driver = driver
	n.log = log
	return n
}

func (n *RemoteNode) Reset() {
	for id := range n.sess {
		n.DeleteSess(id)
	}
	n.sess = make(map[uint64]struct{})
}

func (n *RemoteNode) Sess(lSeid uint64) (*Sess, error) {
	_, ok := n.sess[lSeid]
	if !ok {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}
	return n.local.Sess(lSeid)
}

func (n *RemoteNode) NewSess(rSeid uint64) *Sess {
	s := n.local.NewSess(rSeid, BUFFQ_LEN)
	n.sess[s.LocalID] = struct{}{}
	s.rnode = n
	s.log = n.log.WithField(logger.FieldSessionID, fmt.Sprintf("SEID:L(%#x),R(%#x)", s.LocalID, rSeid))
	s.log.Infoln("New session")
	return s
}

func (n *RemoteNode) DeleteSess(lSeid uint64) {
	_, ok := n.sess[lSeid]
	if !ok {
		return
	}
	delete(n.sess, lSeid)
	err := n.local.DeleteSess(lSeid)
	if err != nil {
		n.log.Warnln(err)
	}
}

type LocalNode struct {
	sess []*Sess
	free []uint64
}

func (n *LocalNode) Reset() {
	for _, sess := range n.sess {
		if sess != nil {
			sess.Close()
		}
	}
	n.sess = []*Sess{}
	n.free = []uint64{}
}

func (n *LocalNode) Sess(lSeid uint64) (*Sess, error) {
	if lSeid == 0 {
		return nil, errors.New("Sess: invalid lSeid:0")
	}
	i := int(lSeid) - 1
	if i >= len(n.sess) {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}
	sess := n.sess[i]
	if sess == nil {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}
	return sess, nil
}

func (n *LocalNode) RemoteSess(rSeid uint64, addr net.Addr) (*Sess, error) {
	for _, s := range n.sess {
		if s.RemoteID == rSeid && s.rnode.addr.String() == addr.String() {
			return s, nil
		}
	}
	return nil, errors.Errorf("RemoteSess: invalid rSeid:%#x, addr:%s ", rSeid, addr)
}

func (n *LocalNode) NewSess(rSeid uint64, qlen int) *Sess {
	s := &Sess{
		RemoteID: rSeid,
		PDRIDs:   make(map[uint16]struct{}),
		FARIDs:   make(map[uint32]struct{}),
		QERIDs:   make(map[uint32]struct{}),
		URRIDs:   make(map[uint32]struct{}),
		BARIDs:   make(map[uint8]struct{}),
		q:        make(map[uint16]chan []byte),
		qlen:     qlen,
	}
	last := len(n.free) - 1
	if last >= 0 {
		s.LocalID = n.free[last]
		n.free = n.free[:last]
		n.sess[s.LocalID-1] = s
	} else {
		n.sess = append(n.sess, s)
		s.LocalID = uint64(len(n.sess))
	}
	return s
}

func (n *LocalNode) DeleteSess(lSeid uint64) error {
	if lSeid == 0 {
		return errors.New("DeleteSess: invalid lSeid:0")
	}
	i := int(lSeid) - 1
	if i >= len(n.sess) {
		return errors.Errorf("DeleteSess: sess not found (lSeid:%#x)", lSeid)
	}
	if n.sess[i] == nil {
		return errors.Errorf("DeleteSess: sess not found (lSeid:%#x)", lSeid)
	}
	n.sess[i].log.Infoln("sess deleted")
	n.sess[i].Close()
	n.sess[i] = nil
	n.free = append(n.free, lSeid)
	return nil
}
