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
	"github.com/free5gc/go-upf/pkg/factory"
)

type Sess struct {
	node     *RemoteNode
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
	s.DropReport()
}

func (s *Sess) CreatePDR(req *ie.IE) error {
	err := s.node.driver.CreatePDR(s.LocalID, req)
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
	return s.node.driver.UpdatePDR(s.LocalID, req)
}

func (s *Sess) RemovePDR(req *ie.IE) error {
	err := s.node.driver.RemovePDR(s.LocalID, req)
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
	err := s.node.driver.CreateFAR(s.LocalID, req)
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
	return s.node.driver.UpdateFAR(s.LocalID, req)
}

func (s *Sess) RemoveFAR(req *ie.IE) error {
	err := s.node.driver.RemoveFAR(s.LocalID, req)
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
	err := s.node.driver.CreateQER(s.LocalID, req)
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
	return s.node.driver.UpdateQER(s.LocalID, req)
}

func (s *Sess) RemoveQER(req *ie.IE) error {
	err := s.node.driver.RemoveQER(s.LocalID, req)
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
	s.node.driver.HandleReport(s.LocalID, s)
}

func (s *Sess) DropReport() {
	s.node.driver.DropReport(s.LocalID)
	s.handler = nil
}

func (s *Sess) ServeReport(r report.Report) {
	if s.handler == nil {
		return
	}
	addr := fmt.Sprintf("%s:%d", s.node.ID, factory.UpfPfcpDefaultPort)
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	s.handler(laddr, s.RemoteID, r)
}

type RemoteNode struct {
	ID     string
	local  *LocalNode
	sess   map[uint64]struct{}
	driver forwarder.Driver
	log    *logrus.Entry
}

func NewRemoteNode(id string, local *LocalNode, driver forwarder.Driver, log *logrus.Entry) *RemoteNode {
	n := new(RemoteNode)
	n.ID = id
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
		return nil, errors.Errorf("Sess: sess not found (lSeid:0x%x)", lSeid)
	}
	return n.local.Sess(lSeid)
}

func (n *RemoteNode) NewSess(rSeid uint64) *Sess {
	s := n.local.NewSess(rSeid)
	n.sess[s.LocalID] = struct{}{}
	s.node = n
	s.log = n.log.WithField(logger.FieldSessionID, fmt.Sprintf("SEID:L(0x%x),R(0x%x)", s.LocalID, rSeid))
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
		return nil, errors.Errorf("Sess: sess not found (lSeid:0x%x)", lSeid)
	}
	sess := n.sess[i]
	if sess == nil {
		return nil, errors.Errorf("Sess: sess not found (lSeid:0x%x)", lSeid)
	}
	return sess, nil
}

func (n *LocalNode) NewSess(rSeid uint64) *Sess {
	s := &Sess{
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
	return s
}

func (n *LocalNode) DeleteSess(lSeid uint64) error {
	if lSeid == 0 {
		return errors.New("DeleteSess: invalid lSeid:0")
	}
	i := int(lSeid) - 1
	if i >= len(n.sess) {
		return errors.Errorf("DeleteSess: sess not found (lSeid:0x%x)", lSeid)
	}
	if n.sess[i] == nil {
		return errors.Errorf("DeleteSess: sess not found (lSeid:0x%x)", lSeid)
	}
	n.sess[i].log.Infoln("sess deleted")
	n.sess[i].Close()
	n.sess[i] = nil
	n.free = append(n.free, lSeid)
	return nil
}
