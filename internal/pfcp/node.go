package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

type Sess struct {
	node     *Node
	LocalID  uint64
	RemoteID uint64
	PDRIDs   map[uint16]struct{}
	FARIDs   map[uint32]struct{}
	QERIDs   map[uint32]struct{}
	handler  func(net.Addr, uint64, report.Report)
}

func NewSess() *Sess {
	s := new(Sess)
	s.PDRIDs = make(map[uint16]struct{})
	s.FARIDs = make(map[uint32]struct{})
	s.QERIDs = make(map[uint32]struct{})
	return s
}

func (s *Sess) Close() {
	for id := range s.FARIDs {
		i := ie.NewRemoveFAR(ie.NewFARID(id))
		s.RemoveFAR(i)
	}
	for id := range s.QERIDs {
		i := ie.NewRemoveQER(ie.NewQERID(id))
		s.RemoveQER(i)
	}
	for id := range s.PDRIDs {
		i := ie.NewRemovePDR(ie.NewPDRID(id))
		s.RemovePDR(i)
	}
}

func (s *Sess) CreatePDR(req *ie.IE) error {
	err := s.node.driver.CreatePDR(req)
	if err == nil {
		id, err := req.PDRID()
		if err != nil {
			return err
		}
		s.PDRIDs[id] = struct{}{}
	}
	return err
}

func (s *Sess) UpdatePDR(req *ie.IE) error {
	return s.node.driver.UpdatePDR(req)
}

func (s *Sess) RemovePDR(req *ie.IE) error {
	err := s.node.driver.RemovePDR(req)
	if err == nil {
		id, err := req.PDRID()
		if err != nil {
			return err
		}
		delete(s.PDRIDs, id)
	}
	return err
}

func (s *Sess) CreateFAR(req *ie.IE) error {
	err := s.node.driver.CreateFAR(req)
	if err == nil {
		id, err := req.FARID()
		if err != nil {
			return err
		}
		s.FARIDs[id] = struct{}{}
	}
	return err
}

func (s *Sess) UpdateFAR(req *ie.IE) error {
	return s.node.driver.UpdateFAR(req)
}

func (s *Sess) RemoveFAR(req *ie.IE) error {
	err := s.node.driver.RemoveFAR(req)
	if err == nil {
		id, err := req.FARID()
		if err != nil {
			return err
		}
		delete(s.FARIDs, id)
	}
	return err
}

func (s *Sess) CreateQER(req *ie.IE) error {
	err := s.node.driver.CreateQER(req)
	if err == nil {
		id, err := req.QERID()
		if err != nil {
			return err
		}
		s.QERIDs[id] = struct{}{}
	}
	return err
}

func (s *Sess) UpdateQER(req *ie.IE) error {
	return s.node.driver.UpdateQER(req)
}

func (s *Sess) RemoveQER(req *ie.IE) error {
	err := s.node.driver.RemoveQER(req)
	if err == nil {
		id, err := req.QERID()
		if err != nil {
			return err
		}
		delete(s.QERIDs, id)
	}
	return err
}

func (s *Sess) HandleReport(handler func(net.Addr, uint64, report.Report)) {
	s.handler = handler
	s.node.driver.HandleReport(s)
}

func (s *Sess) ServeReport(r report.Report) {
	if s.handler == nil {
		return
	}
	addr := s.node.ID + ":8805"
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	s.handler(laddr, s.RemoteID, r)
}

type Node struct {
	ID     string
	sess   []*Sess
	free   []uint64
	driver forwarder.Driver
}

func NewNode(id string, driver forwarder.Driver) *Node {
	n := new(Node)
	n.ID = id
	n.driver = driver
	return n
}

func (n *Node) Reset() {
	for _, sess := range n.sess {
		if sess != nil {
			sess.Close()
		}
	}
	n.sess = []*Sess{}
	n.free = []uint64{}
}

func (n *Node) Sess(seid uint64) (*Sess, bool) {
	if seid == 0 {
		return nil, false
	}
	i := int(seid) - 1
	if i >= len(n.sess) {
		return nil, false
	}
	sess := n.sess[i]
	return sess, sess != nil
}

func (n *Node) New(seid uint64) *Sess {
	sess := NewSess()
	sess.node = n
	sess.RemoteID = seid
	last := len(n.free) - 1
	if last >= 0 {
		sess.LocalID = n.free[last]
		n.free = n.free[:last]
		n.sess[sess.LocalID-1] = sess
	} else {
		n.sess = append(n.sess, sess)
		sess.LocalID = uint64(len(n.sess))
	}
	return sess
}

func (n *Node) Delete(seid uint64) {
	if seid == 0 {
		return
	}
	i := int(seid) - 1
	if i >= len(n.sess) {
		return
	}
	if n.sess[i] == nil {
		return
	}
	n.sess[i].Close()
	n.sess[i] = nil
	n.free = append(n.free, seid)
}
