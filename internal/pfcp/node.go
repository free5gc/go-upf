package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
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
	for id := range s.PDRIDs {
		i := ie.NewRemovePDR(ie.NewPDRID(id))
		err := s.RemovePDR(i)
		if err != nil {
			s.log.Errorf("remove PDR err: %+v", err)
		}
	}
}

func (s *Sess) CreatePDR(req *ie.IE) error {
	err := s.node.driver.CreatePDR(req)
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
	return s.node.driver.UpdatePDR(req)
}

func (s *Sess) RemovePDR(req *ie.IE) error {
	err := s.node.driver.RemovePDR(req)
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
	err := s.node.driver.CreateFAR(req)
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
	return s.node.driver.UpdateFAR(req)
}

func (s *Sess) RemoveFAR(req *ie.IE) error {
	err := s.node.driver.RemoveFAR(req)
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
	err := s.node.driver.CreateQER(req)
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
	return s.node.driver.UpdateQER(req)
}

func (s *Sess) RemoveQER(req *ie.IE) error {
	err := s.node.driver.RemoveQER(req)
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
	log    *logrus.Entry
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

func (n *Node) Sess(lSeid uint64) (*Sess, error) {
	if lSeid == 0 {
		return nil, errors.New("Sess: invalid lSeid:0")
	}
	i := int(lSeid) - 1
	if i >= len(n.sess) {
		return nil, errors.Errorf("Sess: sess not found (lSeid:0x%x)", lSeid)
	}
	sess := n.sess[i]
	if sess == nil {
		return nil, errors.Errorf("Sess: sess not found (lSeid:0x%x)", lSeid)
	}
	return sess, nil
}

func (n *Node) NewSess(rSeid uint64) *Sess {
	s := &Sess{
		node:     n,
		RemoteID: rSeid,
		PDRIDs:   make(map[uint16]struct{}),
		FARIDs:   make(map[uint32]struct{}),
		QERIDs:   make(map[uint32]struct{}),
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
	s.log = n.log.WithField(logger.FieldSessionID, fmt.Sprintf("SEID:L(0x%x),R(0x%x)", s.LocalID, rSeid))
	s.log.Infoln("New session")
	return s
}

func (n *Node) DeleteSess(lSeid uint64) {
	if lSeid == 0 {
		n.log.Warnln("DeleteSess: invalid lSeid:0")
		return
	}
	i := int(lSeid) - 1
	if i >= len(n.sess) {
		n.log.Warnf("DeleteSess: sess not found (lSeid:0x%x)", lSeid)
		return
	}
	if n.sess[i] == nil {
		n.log.Warnf("DeleteSess: sess not found (lSeid:0x%x)", lSeid)
		return
	}
	n.sess[i].log.Infoln("sess deleted")
	n.sess[i].Close()
	n.sess[i] = nil
	n.free = append(n.free, lSeid)
}
