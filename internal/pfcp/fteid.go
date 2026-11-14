package pfcp

import (
	"math/rand/v2"
	"net"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/factory"
)

// fteidAllocator chooses the F-TEIDs that PDRs ask for (TS 29.244 clause 5.5.3). It counts the PDRs that use
// each TEID, whoever allocated it, so that it never chooses one in use.
type fteidAllocator struct {
	addr   net.IP // the IPv4 address of the F-TEIDs that it chooses; FTUP is advertised only with one
	strict bool   // reject a new PDR with an F-TEID of the CP function (clause 5.5.1)
	last   uint32
	teids  map[uint32]*teidUse
}

type teidUse struct {
	owner *Sess // the session that the TEID was chosen for, nil for a TEID of the CP function
	pdrs  int
}

func newFTEIDAllocator(cfg *factory.Config) fteidAllocator {
	addr := fteidAddress(cfg)
	if addr == nil {
		logger.PfcpLog.Warnln("no IPv4 GTP-U address: FTUP is not advertised")
	}
	// A random first TEID: a restarted UPF does not reuse at once the TEIDs of its previous run (TS 23.527
	// clause 4.3.2).
	return fteidAllocator{addr: addr, strict: cfg.Pfcp.StrictFTEIDAllocation, last: rand.Uint32()}
}

// fteidAddress is the GTP-U address that the forwarder listens on, the first one of gtpu.ifList, or the
// address of the Node ID when the forwarder listens on every address.
func fteidAddress(cfg *factory.Config) net.IP {
	if cfg.Gtpu != nil && len(cfg.Gtpu.IfList) > 0 {
		addr, err := net.ResolveIPAddr("ip4", cfg.Gtpu.IfList[0].Addr)
		if err == nil && !addr.IP.IsUnspecified() {
			return addr.IP.To4()
		}
	}
	addr, err := net.ResolveIPAddr("ip4", cfg.Pfcp.NodeID)
	if err != nil || addr.IP.IsUnspecified() {
		return nil
	}
	return addr.IP.To4()
}

// hold counts a PDR that has teid in its Local F-TEID.
func (a *fteidAllocator) hold(teid uint32) {
	if teid == 0 {
		return
	}
	if a.teids == nil {
		a.teids = make(map[uint32]*teidUse)
	}
	use, ok := a.teids[teid]
	if !ok {
		use = &teidUse{}
		a.teids[teid] = use
	}
	use.pdrs++
}

// drop uncounts a PDR that had teid in its Local F-TEID, and frees the TEID if no PDR has it any more.
func (a *fteidAllocator) drop(teid uint32) {
	use, ok := a.teids[teid]
	if !ok {
		return
	}
	use.pdrs--
	if use.pdrs <= 0 {
		delete(a.teids, teid)
	}
}

// choose allocates to sess a TEID that no PDR uses and that is not in named.
func (a *fteidAllocator) choose(sess *Sess, named map[uint32]struct{}) uint32 {
	if a.teids == nil {
		a.teids = make(map[uint32]*teidUse)
	}
	for {
		a.last++
		_, used := a.teids[a.last]
		_, isNamed := named[a.last]
		if a.last != 0 && !used && !isNamed {
			a.teids[a.last] = &teidUse{owner: sess}
			return a.last
		}
	}
}

// fteidRequest is the F-TEID allocation of one PFCP Session Establishment or Modification Request.
type fteidRequest struct {
	sess       *Sess
	alloc      *fteidAllocator
	restoring  bool                // the Restoration Indication of an establishment
	named      map[uint32]struct{} // the TEIDs of the CP function in the request's PDRs
	byChooseID map[uint8]uint32
	chosen     []uint32
	created    map[uint16]uint32 // the TEID chosen for a Create PDR, by PDR ID
}

func (s *Sess) newFTEIDRequest(restoring bool, pdrLists ...[]*ie.IE) *fteidRequest {
	r := &fteidRequest{
		sess:       s,
		alloc:      &s.rnode.local.fteids,
		restoring:  restoring,
		named:      make(map[uint32]struct{}),
		byChooseID: make(map[uint8]uint32),
		created:    make(map[uint16]uint32),
	}
	for _, pdrs := range pdrLists {
		for _, pdr := range pdrs {
			if teid, _ := localTEIDOf(pdr); teid != 0 {
				r.named[teid] = struct{}{}
			}
		}
	}
	return r
}

// release frees the TEIDs that the request chose and no PDR took, those of a request that was rejected.
func (r *fteidRequest) release() {
	for _, teid := range r.chosen {
		if use, ok := r.alloc.teids[teid]; ok && use.pdrs == 0 {
			delete(r.alloc.teids, teid)
		}
	}
}

// createPDR gives the Create PDR to install: with the F-TEID that the UP function chose, if its Local F-TEID
// has CH.
func (r *fteidRequest) createPDR(req *ie.IE) (*ie.IE, error) {
	ies, err := req.CreatePDR()
	if err != nil {
		return req, nil
	}
	ies, changed, err := r.localFTEID(ies, true)
	if err != nil || !changed {
		return req, err
	}
	return ie.NewCreatePDR(ies...), nil
}

// checkUpdatePDR checks the Local F-TEID of an Update PDR.
func (r *fteidRequest) checkUpdatePDR(req *ie.IE) error {
	ies, err := req.UpdatePDR()
	if err != nil {
		return nil
	}
	_, _, err = r.localFTEID(ies, false)
	return err
}

// localFTEID replaces among the IEs of a Create PDR a Local F-TEID that has CH with the F-TEID that the UP
// function chose, or checks one that the CP function allocated. An IE that does not parse is left to the
// forwarder's plan.
func (r *fteidRequest) localFTEID(ies []*ie.IE, create bool) ([]*ie.IE, bool, error) {
	var pdrID uint16
	pdiAt := -1
	for n, i := range ies {
		switch i.Type {
		case ie.PDRID:
			if id, idErr := i.PDRID(); idErr == nil {
				pdrID = id
			}
		case ie.PDI:
			pdiAt = n
		}
	}
	if pdiAt < 0 {
		return ies, false, nil
	}
	pdi, err := ies[pdiAt].PDI()
	if err != nil {
		return ies, false, nil
	}
	for n, i := range pdi {
		if i.Type != ie.FTEID {
			continue
		}
		fteid, parseErr := i.FTEID()
		if parseErr != nil {
			return ies, false, nil
		}
		if !fteid.HasCh() {
			return ies, false, r.checkCPAllocated(pdrID, fteid.TEID, create)
		}
		// On N4, no Updated PDR returns an F-TEID that the UP function chose (Table 7.5.5.5-1).
		if !create {
			return ies, false, ErrRuleCreationModificationFailed
		}
		teid, chooseErr := r.choose(fteid)
		if chooseErr != nil {
			return ies, false, chooseErr
		}
		r.created[pdrID] = teid
		pdi[n] = r.fteid(teid)
		ies[pdiAt] = ie.NewPDI(pdi...)
		return ies, true, nil
	}
	return ies, false, nil
}

func (r *fteidRequest) choose(fteid *ie.FTEIDFields) (uint32, error) {
	// The UP function has no IPv6 GTP-U address.
	if r.alloc.addr == nil || !fteid.HasIPv4() {
		return 0, ErrRuleCreationModificationFailed
	}
	if fteid.HasChID() {
		if teid, ok := r.byChooseID[fteid.ChooseID]; ok {
			return teid, nil
		}
	}
	teid := r.alloc.choose(r.sess, r.named)
	r.chosen = append(r.chosen, teid)
	if fteid.HasChID() {
		r.byChooseID[fteid.ChooseID] = teid
	}
	return teid, nil
}

// checkCPAllocated takes or rejects a Local F-TEID that the CP function allocated.
func (r *fteidRequest) checkCPAllocated(pdrID uint16, teid uint32, create bool) error {
	use, held := r.alloc.teids[teid]
	if r.restoring {
		// A restored session has its F-TEID (Table 7.5.2.1-1 NOTE 4). Another session having it is not expected
		// (TS 23.527 clause 4.3.2) and has no cause of its own: 86 is excluded there, 71 by Table 8.2.1-1.
		if held {
			return ErrFTEIDInUse
		}
		return nil
	}
	// A new PDR has an F-TEID of the UP function, an updated one keeps its own (clause 5.5.1).
	if r.alloc.strict && (create || teid != r.localTEID(pdrID)) {
		return ErrInvalidFTEIDAllocation
	}
	// A TEID that the UP function chose belongs to its session.
	if held && use.owner != nil && use.owner != r.sess {
		return ErrInvalidFTEIDAllocation
	}
	return nil
}

// localTEID is the TEID of the PDR's Local F-TEID, before the request or as the request creates it.
func (r *fteidRequest) localTEID(pdrID uint16) uint32 {
	if info, ok := r.sess.PDRIDs[pdrID]; ok {
		return info.LocalTEID
	}
	return r.created[pdrID]
}

// fteid is the Local F-TEID of a Created PDR.
func (r *fteidRequest) fteid(teid uint32) *ie.IE {
	return ie.NewFTEID(0x01, teid, r.alloc.addr, nil, 0)
}

// localTEIDOf is the TEID of the Local F-TEID of a Create PDR or an Update PDR, and whether the PDR has a PDI:
// an Update PDR without one keeps its F-TEID.
func localTEIDOf(pdr *ie.IE) (uint32, bool) {
	if pdr == nil {
		return 0, false
	}
	var ies []*ie.IE
	var err error
	switch pdr.Type {
	case ie.CreatePDR:
		ies, err = pdr.CreatePDR()
	case ie.UpdatePDR:
		ies, err = pdr.UpdatePDR()
	default:
		return 0, false
	}
	if err != nil {
		return 0, false
	}
	for _, i := range ies {
		if i.Type != ie.PDI {
			continue
		}
		fteid, fteidErr := i.FTEID()
		if fteidErr != nil {
			return 0, true
		}
		return fteid.TEID, true
	}
	return 0, false
}
