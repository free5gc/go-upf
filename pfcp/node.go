package pfcp

import (
	"github.com/m-asama/upf/forwarder"
	"github.com/wmnsk/go-pfcp/ie"
)

type Sess struct {
	node     *Node
	LocalID  uint64
	RemoteID uint64
	PDRIDs   map[uint16]struct{}
	FARIDs   map[uint32]struct{}
	QERIDs   map[uint32]struct{}
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
	if seid >= uint64(len(n.sess)) {
		return nil, false
	}
	sess := n.sess[seid]
	return sess, sess != nil
}

func (n *Node) New(seid uint64) *Sess {
	sess := NewSess()
	sess.node = n
	sess.RemoteID = seid
	l := len(n.free)
	if l != 0 {
		sess.LocalID = n.free[l-1]
		n.free = n.free[:l-1]
		n.sess[sess.LocalID] = sess
	} else {
		sess.LocalID = uint64(len(n.sess))
		n.sess = append(n.sess, sess)
	}
	return sess
}

func (n *Node) Delete(seid uint64) {
	if seid < uint64(len(n.sess)) {
		n.sess[seid].Close()
		n.sess[seid] = nil
	}
	n.free = append(n.free, seid)
}
