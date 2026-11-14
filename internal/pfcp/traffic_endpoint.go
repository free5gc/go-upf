package pfcp

import (
	"maps"
	"slices"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
)

// Traffic Endpoints, the PDI optimization (TS 29.244 clause 5.2.1A.2): the PDI IEs that several PDRs of a
// session share, which the PDRs name by the Traffic Endpoint ID. The forwarder knows PDRs only: a PDR that
// refers to a Traffic Endpoint is installed with the IEs of the Traffic Endpoint in its PDI.

// trafficEndpoint is a Traffic Endpoint of a session: its IEs but its ID, with the Local F-TEID that the UP
// function chose.
type trafficEndpoint struct {
	ies []*ie.IE
}

// endpointRef is how the PDI of a PDR refers to a Traffic Endpoint: its ID, and the PDI's IEs as the CP function
// sent them.
type endpointRef struct {
	id  uint8
	pdi []*ie.IE
}

// localTEID is the TEID of the Traffic Endpoint's Local F-TEID, 0 for none.
func (te *trafficEndpoint) localTEID() uint32 {
	if te == nil {
		return 0
	}
	for _, i := range te.ies {
		if i.Type == ie.FTEID {
			if fteid, err := i.FTEID(); err == nil {
				return fteid.TEID
			}
		}
	}
	return 0
}

// pdi is the PDI that the forwarder installs for a PDR that refers to the Traffic Endpoint: the PDR's own IEs,
// and those of the Traffic Endpoint.
func (te *trafficEndpoint) pdi(ref *endpointRef) *ie.IE {
	return ie.NewPDI(slices.Concat(ref.pdi, te.ies)...)
}

func isTrafficEndpointID(i *ie.IE) bool {
	return i.Type == ie.TrafficEndpointID
}

func isFTEID(i *ie.IE) bool {
	return i.Type == ie.FTEID
}

// endpoint is the Traffic Endpoint id as the request leaves it, nil if it does not exist or the request
// removes it.
func (r *fteidRequest) endpoint(id uint8) *trafficEndpoint {
	if _, removed := r.removedEndpoints[id]; removed {
		return nil
	}
	if te, ok := r.endpoints[id]; ok {
		return te
	}
	return r.sess.trafficEndpoints[id]
}

// takeEndpoints takes the Create, Update and Remove Traffic Endpoint IEs of a request, before its PDRs.
func (r *fteidRequest) takeEndpoints(create, update, remove []*ie.IE) error {
	for _, req := range create {
		id, err := req.TrafficEndpointID()
		ies, iesErr := req.CreateTrafficEndpoint()
		if err != nil || iesErr != nil {
			return ErrMissingMandatoryIE
		}
		if r.endpoint(id) != nil {
			return ErrRuleCreationModificationFailed
		}
		if err = r.setEndpoint(id, nil, ies); err != nil {
			return err
		}
	}
	for _, req := range update {
		id, err := req.TrafficEndpointID()
		ies, iesErr := req.UpdateTrafficEndpoint()
		if err != nil || iesErr != nil {
			return ErrMissingMandatoryIE
		}
		old := r.endpoint(id)
		if old == nil {
			return ErrRuleNotFound
		}
		if err = r.setEndpoint(id, old, ies); err != nil {
			return err
		}
	}
	for _, req := range remove {
		id, err := req.TrafficEndpointID()
		if err != nil {
			return ErrMissingMandatoryIE
		}
		if r.endpoint(id) == nil {
			return ErrRuleNotFound
		}
		// A request does not create or update and remove one Traffic Endpoint (clause 6.3.3.2).
		if _, set := r.endpoints[id]; set {
			return ErrMutualExclusionConflict
		}
		r.removedEndpoints[id] = struct{}{}
	}
	return nil
}

// referTo puts in ies[at] the PDI of a PDR that refers to a Traffic Endpoint (clause 5.2.1A.2).
func (r *fteidRequest) referTo(ies []*ie.IE, at int, pdrID uint16, ref *endpointRef) ([]*ie.IE, bool, error) {
	te := r.endpoint(ref.id)
	if te == nil {
		return ies, false, ErrRuleCreationModificationFailed
	}
	r.endpointRefs[pdrID] = ref
	ies[at] = te.pdi(ref)
	return ies, true, nil
}

// setEndpoint keeps the Traffic Endpoint id as the request leaves it: the IEs of a Create Traffic Endpoint, or
// those of an Update Traffic Endpoint and those of old that they do not replace (Table 7.5.4.13-1 NOTE 1). Its
// Local F-TEID is taken as that of a PDR.
func (r *fteidRequest) setEndpoint(id uint8, old *trafficEndpoint, ies []*ie.IE) error {
	ies = slices.DeleteFunc(ies, isTrafficEndpointID)
	teid, err := r.localFTEID(ies, old.localTEID(), old == nil)
	if err != nil {
		return err
	}
	if teid != 0 {
		r.chosenEndpoints[id] = teid
	}
	te := &trafficEndpoint{}
	if old != nil {
		replaced := make(map[uint16]bool, len(ies))
		for _, i := range ies {
			replaced[i.Type] = true
		}
		for _, i := range old.ies {
			if !replaced[i.Type] {
				te.ies = append(te.ies, i)
			}
		}
	}
	te.ies = append(te.ies, ies...)
	r.endpoints[id] = te
	return nil
}

// endpointPDRPlans are the plans that the request's Traffic Endpoints bring to the PDRs that refer to them and
// that the request leaves as they are: the removal of those of a removed Traffic Endpoint, an Update PDR with the
// IEs of an updated one.
func (r *fteidRequest) endpointPDRPlans(plan *forwarder.ModificationPlan) error {
	touched := make(map[uint16]bool)
	for _, plans := range [][]*forwarder.PDRPlan{plan.CreatePDRs, plan.UpdatePDRs, plan.RemovePDRs} {
		for _, p := range plans {
			touched[p.PDRID] = true
		}
	}
	for _, pdrID := range slices.Sorted(maps.Keys(r.sess.PDRIDs)) {
		ref := r.sess.PDRIDs[pdrID].endpoint
		if ref == nil || touched[pdrID] {
			continue
		}
		if _, removed := r.removedEndpoints[ref.id]; removed {
			p, err := r.sess.rnode.driver.BuildRemovePDRPlan(r.sess.LocalID, ie.NewRemovePDR(ie.NewPDRID(pdrID)))
			if err != nil {
				return ErrRuleCreationModificationFailed
			}
			plan.RemovePDRs = append(plan.RemovePDRs, p)
			continue
		}
		// An existing Traffic Endpoint in the request is an updated one.
		te, updated := r.endpoints[ref.id]
		if !updated {
			continue
		}
		update := ie.NewUpdatePDR(ie.NewPDRID(pdrID), te.pdi(ref))
		p, err := r.sess.rnode.driver.BuildUpdatePDRPlan(r.sess.LocalID, update)
		if err != nil {
			return ErrRuleCreationModificationFailed
		}
		// The PDR keeps its URRs, which a plan without URR IDs dissociates.
		p.URRIDs = slices.Collect(maps.Keys(r.sess.PDRIDs[pdrID].RelatedURRIDs))
		plan.UpdatePDRs = append(plan.UpdatePDRs, p)
	}
	return nil
}

// commitEndpoints applies the request's Traffic Endpoints to the session once its rules are applied, and keeps the
// Traffic Endpoint that each PDR refers to, for the requests that update it.
func (r *fteidRequest) commitEndpoints() {
	for id, te := range r.endpoints {
		r.alloc.hold(te.localTEID())
		r.alloc.drop(r.sess.trafficEndpoints[id].localTEID())
		r.sess.trafficEndpoints[id] = te
	}
	for id := range r.removedEndpoints {
		r.alloc.drop(r.sess.trafficEndpoints[id].localTEID())
		delete(r.sess.trafficEndpoints, id)
	}
	for pdrID, ref := range r.endpointRefs {
		if info, ok := r.sess.PDRIDs[pdrID]; ok {
			info.endpoint = ref
		}
	}
}

// createdEndpoints are the Created Traffic Endpoint IEs of the response: the Traffic Endpoints whose Local
// F-TEID the UP function chose (Table 7.5.3.5-1).
func (r *fteidRequest) createdEndpoints() []*ie.IE {
	var created []*ie.IE
	for _, id := range slices.Sorted(maps.Keys(r.chosenEndpoints)) {
		created = append(created,
			ie.NewCreatedTrafficEndpoint(ie.NewTrafficEndpointID(id), r.fteid(r.chosenEndpoints[id])))
	}
	return created
}
