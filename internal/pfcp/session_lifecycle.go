package pfcp

import (
	"fmt"
	"net"
	"time"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
)

const maxSessionCleanupAttempts = 3

// Close handles UPF-initiated cleanup. An active peer drives retries for its
// own Session Deletion Request.
func (s *Session) Close() ([]report.USAReport, error) {
	if s.deletionRequested {
		return nil, fmt.Errorf("cleanup is waiting for the next Session Deletion Request")
	}
	return s.attemptCleanup()
}

func (s *Session) closeByRequest() ([]report.USAReport, error) {
	s.deletionRequested = true
	return s.attemptCleanup()
}

func (s *Session) attemptCleanup() ([]report.USAReport, error) {
	s.cleanupRetryAt = time.Time{}
	if s.cleanupAttempts >= maxSessionCleanupAttempts {
		return nil, fmt.Errorf("session cleanup exhausted %d attempts", maxSessionCleanupAttempts)
	}
	s.cleanupAttempts++
	reports, err := s.cleanup()
	if err != nil && !s.deletionRequested && s.cleanupAttempts < maxSessionCleanupAttempts {
		delay := time.Second << (s.cleanupAttempts - 1)
		s.cleanupRetryAt = time.Now().Add(delay)
	}
	return reports, err
}

// cleanup retries only outstanding removals. Failed cleanup retains the Session,
// its datapath handle, report metadata and Local SEID until a later attempt.
// Cleanup is best-effort deletion, not a rollback transaction: a failed attempt
// may already have removed some rules. Retries run only while PFCP is running;
// persistent failures retain the SEID rather than recycling it over stale rules.
func (s *Session) cleanup() ([]report.USAReport, error) {
	if !s.closing {
		s.closing = true
		for _, q := range s.q {
			close(q)
		}
		s.q = nil
	}

	changes := &rules.RuleChangeSet{SEID: s.LocalID}
	for id := range s.PDRIDs {
		changes.RemovePDRs = append(changes.RemovePDRs, id)
	}
	for id := range s.FARIDs {
		changes.RemoveFARs = append(changes.RemoveFARs, id)
	}
	for id := range s.QERIDs {
		changes.RemoveQERs = append(changes.RemoveQERs, id)
	}
	for id, info := range s.URRIDs {
		if info.removed {
			continue
		}
		changes.RemoveURRs = append(changes.RemoveURRs, id)
	}
	for id := range s.BARIDs {
		changes.RemoveBARs = append(changes.RemoveBARs, id)
	}

	result, err := s.datapath.Cleanup(changes)
	if result != nil {
		for _, id := range result.Removed.PDRs {
			s.ApplyRemovePDR(id)
		}
		for _, id := range result.Removed.FARs {
			s.ApplyRemoveFAR(id)
		}
		for _, id := range result.Removed.QERs {
			s.ApplyRemoveQER(id)
		}
		for _, id := range result.Removed.URRs {
			s.ApplyRemoveURR(id)
		}
		for _, id := range result.Removed.BARs {
			s.ApplyRemoveBAR(id)
		}
		for _, r := range result.USAReports {
			r.USARTrigger.Flags |= report.USAR_TRIG_TERMR
			s.cleanupReports = append(s.cleanupReports, r)
		}
	}
	pending := len(s.PDRIDs) + len(s.FARIDs) + len(s.QERIDs) + len(s.BARIDs)
	for _, info := range s.URRIDs {
		if !info.removed {
			pending++
		}
	}
	if err == nil && pending > 0 {
		err = fmt.Errorf("cleanup left %d unconfirmed rules", pending)
	}
	if err != nil {
		return nil, err
	}
	for id, endpoint := range s.trafficEndpoints {
		s.fteids.drop(endpoint.localTEID())
		delete(s.trafficEndpoints, id)
	}
	reports := s.cleanupReports
	s.cleanupReports = nil
	return reports, nil
}

// Called by the existing PFCP event loop; no worker, extra registry or goroutine.
func (d *Dispatcher) retrySessionCleanup(now time.Time) {
	for seid, deletion := range d.completedDeletions {
		if !now.Before(deletion.expiresAt) {
			delete(d.completedDeletions, seid)
			d.node.sessions.recycleSEID(seid)
		}
	}
	for _, sess := range d.node.sessions.sessions {
		if sess == nil || !sess.closing || sess.cleanupRetryAt.IsZero() || now.Before(sess.cleanupRetryAt) {
			continue
		}
		reports, err := d.node.deleteSession(sess.LocalID)
		if err != nil {
			d.log.Warnf("Session %#x cleanup retry: %v", sess.LocalID, err)
			continue
		}
		if len(reports) == 0 || sess.association == nil {
			continue
		}
		active, ok := d.node.Association(sess.association.PeerNodeID)
		if !ok || active != sess.association {
			continue
		}
		addr := active.peerAddr
		if addr == nil {
			addr, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", active.PeerNodeID, factory.UpfPfcpDefaultPort))
		}
		if err == nil {
			err = d.sendUSAReport(addr, sess, reports)
		}
		if err != nil {
			d.log.Warnf("Session %#x final usage report: %v", sess.LocalID, err)
		}
	}
}
