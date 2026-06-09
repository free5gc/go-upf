package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	logger_util "github.com/free5gc/util/logger"
)

const (
	BUFFQ_LEN = 512
)

type PDRInfo struct {
	RelatedURRIDs map[uint32]struct{}
}

type URRInfo struct {
	removed bool
	SEQN    uint32
	report.MeasureMethod
	report.MeasureInformation
	refPdrNum uint16
}

type Sess struct {
	rnode    *RemoteNode
	LocalID  uint64
	RemoteID uint64
	PDRIDs   map[uint16]*PDRInfo    // key: PDR_ID
	FARIDs   map[uint32]struct{}    // key: FAR_ID
	QERIDs   map[uint32]struct{}    // key: QER_ID
	URRIDs   map[uint32]*URRInfo    // key: URR_ID
	BARIDs   map[uint8]struct{}     // key: BAR_ID
	q        map[uint16]chan []byte // key: PDR_ID
	qlen     int
	log      *logrus.Entry
}

var (
	ErrMissingMandatoryIE             = errors.New("mandatory IE missing or incorrect")
	ErrMissingConditionalIE           = errors.New("conditional IE missing or incorrect")
	ErrRuleNotFound                   = errors.New("rule not found")
	ErrRuleCreationModificationFailed = errors.New("rule creation/modification failed")
	ErrMutualExclusionConflict        = errors.New("conflicting operations on same rule")
)

func (s *Sess) Close() []report.USAReport {
	plan := forwarder.NewModificationPlan(s.LocalID)

	// Build Remove plans for all rules
	for id := range s.FARIDs {
		req := ie.NewRemoveFAR(ie.NewFARID(id))
		p, err := s.rnode.driver.BuildRemoveFARPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveFARPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveFARs = append(plan.RemoveFARs, p)
	}
	for id := range s.QERIDs {
		req := ie.NewRemoveQER(ie.NewQERID(id))
		p, err := s.rnode.driver.BuildRemoveQERPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveQERPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveQERs = append(plan.RemoveQERs, p)
	}
	for id := range s.URRIDs {
		req := ie.NewRemoveURR(ie.NewURRID(id))
		p, err := s.rnode.driver.BuildRemoveURRPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveURRPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveURRs = append(plan.RemoveURRs, p)
	}
	for id := range s.BARIDs {
		req := ie.NewRemoveBAR(ie.NewBARID(id))
		p, err := s.rnode.driver.BuildRemoveBARPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveBARPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveBARs = append(plan.RemoveBARs, p)
	}
	for id := range s.PDRIDs {
		req := ie.NewRemovePDR(ie.NewPDRID(id))
		p, err := s.rnode.driver.BuildRemovePDRPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemovePDRPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemovePDRs = append(plan.RemovePDRs, p)
	}

	// Execute all Remove operations (best-effort)
	execResult, err := s.rnode.driver.ExecuteModificationPlan(plan)
	if err != nil {
		s.log.Errorf("Execute Deletion Plan err: %v", err)
	}

	// Apply state changes and collect USAReports
	var usars []report.USAReport

	for _, p := range plan.RemovePDRs {
		rs := s.ApplyRemovePDR(p)
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}
	for _, p := range plan.RemoveBARs {
		s.ApplyRemoveBAR(p)
	}
	for _, p := range plan.RemoveURRs {
		s.ApplyRemoveURR(p)
	}
	for _, p := range plan.RemoveQERs {
		s.ApplyRemoveQER(p)
	}
	for _, p := range plan.RemoveFARs {
		s.ApplyRemoveFAR(p)
	}

	// Collect USAReports from execution result (RemoveURR)
	if execResult != nil && len(execResult.USAReports) > 0 {
		for i := range execResult.USAReports {
			execResult.USAReports[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
		}
		usars = append(usars, execResult.USAReports...)
	}

	for _, q := range s.q {
		close(q)
	}
	return usars
}

func (s *Sess) diassociateURR(urrid uint32) []report.USAReport {
	urrInfo, ok := s.URRIDs[urrid]
	if !ok {
		return nil
	}

	if urrInfo.refPdrNum > 0 {
		urrInfo.refPdrNum--
		if urrInfo.refPdrNum == 0 {
			// indicates usage report being reported for a URR due to dissociated from the last PDR
			usars, err := s.rnode.driver.QueryURR(s.LocalID, urrid)
			if err != nil {
				return nil
			}
			for i := range usars {
				usars[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
			}
			return usars
		}
	} else {
		s.log.Errorf("diassociateURR: wrong refPdrNum(%d)", urrInfo.refPdrNum)
	}
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

func (s *Sess) URRSeq(urrid uint32) uint32 {
	info, ok := s.URRIDs[urrid]
	if !ok {
		return 0
	}
	seq := info.SEQN
	info.SEQN++
	return seq
}

// ============================================================================
// Validate* methods - validation phase (check state, build plans)
// ============================================================================

// ValidateCreatePDR validates CreatePDR and builds plan without modifying state
func (s *Sess) ValidateCreatePDR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.PDRPlan, error) {
	plan, err := s.rnode.driver.BuildCreatePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	// Validate URR references exist (in session state or in-flight creates)
	for _, urrid := range plan.URRIDs {
		if _, ok := s.URRIDs[urrid]; !ok && !modPlan.HasCreateURR(urrid) {
			return nil, ErrRuleCreationModificationFailed
		}
	}

	return plan, nil
}

// ValidateUpdatePDR validates UpdatePDR and builds plan without modifying state
func (s *Sess) ValidateUpdatePDR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.PDRPlan, error) {
	plan, err := s.rnode.driver.BuildUpdatePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate PDR exists (in session state or in-flight creates)
	if _, ok := s.PDRIDs[plan.PDRID]; !ok && !modPlan.HasCreatePDR(plan.PDRID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemovePDR validates RemovePDR and builds plan without modifying state
func (s *Sess) ValidateRemovePDR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.PDRPlan, error) {
	plan, err := s.rnode.driver.BuildRemovePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate PDR exists (in session state or in-flight creates)
	if _, ok := s.PDRIDs[plan.PDRID]; !ok && !modPlan.HasCreatePDR(plan.PDRID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateFAR validates CreateFAR and builds plan without modifying state
func (s *Sess) ValidateCreateFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.rnode.driver.BuildCreateFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateFAR validates UpdateFAR and builds plan without modifying state
func (s *Sess) ValidateUpdateFAR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.FARPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate FAR exists (in session state or in-flight creates)
	if _, ok := s.FARIDs[plan.FARID]; !ok && !modPlan.HasCreateFAR(plan.FARID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveFAR validates RemoveFAR and builds plan without modifying state
func (s *Sess) ValidateRemoveFAR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.FARPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate FAR exists (in session state or in-flight creates)
	if _, ok := s.FARIDs[plan.FARID]; !ok && !modPlan.HasCreateFAR(plan.FARID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateQER validates CreateQER and builds plan without modifying state
func (s *Sess) ValidateCreateQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.rnode.driver.BuildCreateQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateQER validates UpdateQER and builds plan without modifying state
func (s *Sess) ValidateUpdateQER(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.QERPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate QER exists (in session state or in-flight creates)
	if _, ok := s.QERIDs[plan.QERID]; !ok && !modPlan.HasCreateQER(plan.QERID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveQER validates RemoveQER and builds plan without modifying state
func (s *Sess) ValidateRemoveQER(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.QERPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate QER exists (in session state or in-flight creates)
	if _, ok := s.QERIDs[plan.QERID]; !ok && !modPlan.HasCreateQER(plan.QERID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateURR validates CreateURR and builds plan without modifying state
func (s *Sess) ValidateCreateURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildCreateURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateURR validates UpdateURR and builds plan without modifying state
func (s *Sess) ValidateUpdateURR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate URR exists (in session state or in-flight creates)
	if _, ok := s.URRIDs[plan.URRID]; !ok && !modPlan.HasCreateURR(plan.URRID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveURR validates RemoveURR and builds plan without modifying state
func (s *Sess) ValidateRemoveURR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate URR exists (in session state or in-flight creates)
	if _, ok := s.URRIDs[plan.URRID]; !ok && !modPlan.HasCreateURR(plan.URRID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateQueryURR validates QueryURR and builds plan without modifying state
func (s *Sess) ValidateQueryURR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.URRPlan, error) {
	plan, err := s.rnode.driver.BuildQueryURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate URR exists (in session state or in-flight creates)
	if _, ok := s.URRIDs[plan.QueryURRID]; !ok && !modPlan.HasCreateURR(plan.QueryURRID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateCreateBAR validates CreateBAR and builds plan without modifying state
func (s *Sess) ValidateCreateBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.rnode.driver.BuildCreateBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateBAR validates UpdateBAR and builds plan without modifying state
func (s *Sess) ValidateUpdateBAR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.BARPlan, error) {
	plan, err := s.rnode.driver.BuildUpdateBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate BAR exists (in session state or in-flight creates)
	if _, ok := s.BARIDs[plan.BARID]; !ok && !modPlan.HasCreateBAR(plan.BARID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ValidateRemoveBAR validates RemoveBAR and builds plan without modifying state
func (s *Sess) ValidateRemoveBAR(req *ie.IE, modPlan *forwarder.ModificationPlan) (*forwarder.BARPlan, error) {
	plan, err := s.rnode.driver.BuildRemoveBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	// Validate BAR exists (in session state or in-flight creates)
	if _, ok := s.BARIDs[plan.BARID]; !ok && !modPlan.HasCreateBAR(plan.BARID) {
		return nil, ErrRuleNotFound
	}

	return plan, nil
}

// ============================================================================
// Apply* methods - apply phase (update internal state after execution)
// ============================================================================

// ApplyCreatePDR updates session state after CreatePDR execution
func (s *Sess) ApplyCreatePDR(plan *forwarder.PDRPlan) {
	urrids := make(map[uint32]struct{})
	for _, urrid := range plan.URRIDs {
		urrids[urrid] = struct{}{}
		if urrInfo, ok := s.URRIDs[urrid]; ok {
			urrInfo.refPdrNum++
		}
	}

	s.PDRIDs[plan.PDRID] = &PDRInfo{
		RelatedURRIDs: urrids,
	}
}

// ApplyUpdatePDR updates session state after UpdatePDR execution
// Returns USAReports from disassociated URRs
func (s *Sess) ApplyUpdatePDR(plan *forwarder.PDRPlan) []report.USAReport {
	pdrInfo, ok := s.PDRIDs[plan.PDRID]
	if !ok {
		return nil
	}

	newUrrids := make(map[uint32]struct{})
	for _, urrid := range plan.URRIDs {
		newUrrids[urrid] = struct{}{}
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		if _, ok := newUrrids[urrid]; !ok {
			usar := s.diassociateURR(urrid)
			if len(usar) > 0 {
				usars = append(usars, usar...)
			}
		}
	}
	pdrInfo.RelatedURRIDs = newUrrids

	return usars
}

// ApplyRemovePDR updates session state after RemovePDR execution
// Returns USAReports from disassociated URRs
func (s *Sess) ApplyRemovePDR(plan *forwarder.PDRPlan) []report.USAReport {
	pdrInfo, ok := s.PDRIDs[plan.PDRID]
	if !ok {
		return nil
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		usar := s.diassociateURR(urrid)
		if len(usar) > 0 {
			usars = append(usars, usar...)
		}
	}
	delete(s.PDRIDs, plan.PDRID)

	return usars
}

// ApplyCreateFAR updates session state after CreateFAR execution
func (s *Sess) ApplyCreateFAR(plan *forwarder.FARPlan) {
	s.FARIDs[plan.FARID] = struct{}{}
}

// ApplyRemoveFAR updates session state after RemoveFAR execution
func (s *Sess) ApplyRemoveFAR(plan *forwarder.FARPlan) {
	delete(s.FARIDs, plan.FARID)
}

// ApplyCreateQER updates session state after CreateQER execution
func (s *Sess) ApplyCreateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = struct{}{}
}

// ApplyRemoveQER updates session state after RemoveQER execution
func (s *Sess) ApplyRemoveQER(plan *forwarder.QERPlan) {
	delete(s.QERIDs, plan.QERID)
}

// ApplyCreateURR updates session state after CreateURR execution
func (s *Sess) ApplyCreateURR(plan *forwarder.URRPlan) {
	mInfo := &ie.IE{}
	if plan.MeasureInfoIE != nil {
		mInfo = plan.MeasureInfoIE
	}

	s.URRIDs[plan.URRID] = &URRInfo{
		MeasureMethod: report.MeasureMethod{
			DURAT: plan.OriginalIE.HasDURAT(),
			VOLUM: plan.OriginalIE.HasVOLUM(),
			EVENT: plan.OriginalIE.HasEVENT(),
		},
		MeasureInformation: report.MeasureInformation{
			MBQE: mInfo.HasMBQE(),
			INAM: mInfo.HasINAM(),
			RADI: mInfo.HasRADI(),
			ISTM: mInfo.HasISTM(),
			MNOP: mInfo.HasMNOP(),
		},
	}
}

// ApplyUpdateURR updates session state after UpdateURR execution
func (s *Sess) ApplyUpdateURR(plan *forwarder.URRPlan) {
	urrInfo, ok := s.URRIDs[plan.URRID]
	if !ok {
		return
	}

	// Update MeasureMethod if present in the plan
	if plan.MeasureMethod != 0 {
		urrInfo.DURAT = (plan.MeasureMethod & 0x01) != 0
		urrInfo.VOLUM = (plan.MeasureMethod & 0x02) != 0
		urrInfo.EVENT = (plan.MeasureMethod & 0x04) != 0
	}

	// Update MeasureInformation if present
	if plan.MeasureInfoIE != nil {
		urrInfo.MBQE = plan.MeasureInfoIE.HasMBQE()
		urrInfo.INAM = plan.MeasureInfoIE.HasINAM()
		urrInfo.RADI = plan.MeasureInfoIE.HasRADI()
		urrInfo.ISTM = plan.MeasureInfoIE.HasISTM()
		urrInfo.MNOP = plan.MeasureInfoIE.HasMNOP()
	}
}

// ApplyRemoveURR updates session state after RemoveURR execution
func (s *Sess) ApplyRemoveURR(plan *forwarder.URRPlan) {
	if info, ok := s.URRIDs[plan.URRID]; ok {
		info.removed = true
	}
}

// ApplyCreateBAR updates session state after CreateBAR execution
func (s *Sess) ApplyCreateBAR(plan *forwarder.BARPlan) {
	s.BARIDs[plan.BARID] = struct{}{}
}

// ApplyRemoveBAR updates session state after RemoveBAR execution
func (s *Sess) ApplyRemoveBAR(plan *forwarder.BARPlan) {
	delete(s.BARIDs, plan.BARID)
}

// CleanupRemovedURRs removes URRInfo entries marked as removed
func (s *Sess) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
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
	s.log = n.log.WithFields(
		logrus.Fields{
			logger_util.FieldUserPlaneSEID:    fmt.Sprintf("%#x", s.LocalID),
			logger_util.FieldControlPlaneSEID: fmt.Sprintf("%#x", rSeid),
		})
	s.log.Infoln("New session")
	return s
}

func (n *RemoteNode) DeleteSess(lSeid uint64) []report.USAReport {
	_, ok := n.sess[lSeid]
	if !ok {
		return nil
	}
	delete(n.sess, lSeid)
	usars, err := n.local.DeleteSess(lSeid)
	if err != nil {
		n.log.Warnln(err)
		return nil
	}
	return usars
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

	// Length as int; compare as uint64 to match lSeid type.
	sessLen := len(n.sess)
	if lSeid > uint64(sessLen) {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}

	// Safe: 1 <= lSeid <= sessLen guarantees the conversion and index are valid.
	idx := int(lSeid) - 1
	sess := n.sess[idx]
	if sess == nil {
		return nil, errors.Errorf("Sess: sess not found (lSeid:%#x)", lSeid)
	}
	return sess, nil
}

func (n *LocalNode) RemoteSess(rSeid uint64, addr net.Addr) (*Sess, error) {
	addrString := ""
	if addr != nil {
		addrString = addr.String()
	}

	for _, s := range n.sess {
		if s == nil || s.rnode == nil || s.rnode.addr == nil {
			continue
		}
		if s.RemoteID == rSeid && s.rnode.addr.String() == addrString {
			return s, nil
		}
	}
	return nil, errors.Errorf("RemoteSess: invalid rSeid:%#x, addr:%s ", rSeid, addr)
}

func (n *LocalNode) NewSess(rSeid uint64, qlen int) *Sess {
	s := &Sess{
		RemoteID: rSeid,
		PDRIDs:   make(map[uint16]*PDRInfo),
		FARIDs:   make(map[uint32]struct{}),
		QERIDs:   make(map[uint32]struct{}),
		URRIDs:   make(map[uint32]*URRInfo),
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

func (n *LocalNode) DeleteSess(lSeid uint64) ([]report.USAReport, error) {
	if lSeid == 0 {
		return nil, errors.New("DeleteSess: invalid lSeid:0")
	}

	// Capacity as int; compare as uint64 to match lSeid type.
	sessCap := len(n.sess)
	if lSeid > uint64(sessCap) {
		return nil, errors.Errorf("DeleteSess: sess not found (lSeid:%#x)", lSeid)
	}

	// Safe: 1 <= lSeid <= sessCap ensures valid conversion and index.
	idx := int(lSeid) - 1
	if n.sess[idx] == nil {
		return nil, errors.Errorf("DeleteSess: sess not found (lSeid:%#x)", lSeid)
	}

	n.sess[idx].log.Infoln("sess deleted")
	usars := n.sess[idx].Close()
	n.sess[idx] = nil
	n.free = append(n.free, lSeid)

	return usars, nil
}
