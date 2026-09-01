package pfcp

import (
	"net"

	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

// SessionStore owns the UPF-wide Local SEID namespace and canonical Session objects.
type SessionStore struct {
	sessions  []*Session
	freeSEIDs []uint64
}

func (s *SessionStore) Get(localSEID uint64) (*Session, error) {
	if localSEID == 0 {
		return nil, errors.New("SessionStore.Get: invalid localSEID:0")
	}

	// Length as int; compare as uint64 to match localSEID type.
	sessionCount := len(s.sessions)
	if localSEID > uint64(sessionCount) {
		return nil, errors.Errorf(
			"SessionStore.Get: session not found (localSEID:%#x)",
			localSEID,
		)
	}

	// Safe: 1 <= localSEID <= sessionCount guarantees a valid index.
	index := int(localSEID) - 1
	sess := s.sessions[index]
	if sess == nil {
		return nil, errors.Errorf(
			"SessionStore.Get: session not found (localSEID:%#x)",
			localSEID,
		)
	}
	return sess, nil
}

func (s *SessionStore) FindByRemoteSEID(
	remoteSEID uint64,
	peerAddr net.Addr,
) (*Session, error) {
	peerAddrString := ""
	if peerAddr != nil {
		peerAddrString = peerAddr.String()
	}

	for _, sess := range s.sessions {
		if sess == nil || sess.association == nil || sess.association.peerAddr == nil {
			continue
		}
		if sess.RemoteID == remoteSEID &&
			sess.association.peerAddr.String() == peerAddrString {
			return sess, nil
		}
	}
	return nil, errors.Errorf(
		"SessionStore.FindByRemoteSEID: session not found (remoteSEID:%#x, addr:%s)",
		remoteSEID,
		peerAddr,
	)
}

func (s *SessionStore) Create(
	remoteSEID uint64,
	queueLen int,
	driver forwarder.Driver,
) *Session {
	sess := &Session{
		RemoteID: remoteSEID,
		driver:   driver,
		PDRIDs:   make(map[uint16]*PDRInfo),
		FARIDs:   make(map[uint32]struct{}),
		QERIDs:   make(map[uint32]*QERInfo),
		URRIDs:   make(map[uint32]*URRInfo),
		BARIDs:   make(map[uint8]struct{}),
		q:        make(map[uint16]chan []byte),
		qlen:     queueLen,
	}
	last := len(s.freeSEIDs) - 1
	if last >= 0 {
		sess.LocalID = s.freeSEIDs[last]
		s.freeSEIDs = s.freeSEIDs[:last]
		s.sessions[sess.LocalID-1] = sess
	} else {
		s.sessions = append(s.sessions, sess)
		sess.LocalID = uint64(len(s.sessions))
	}
	return sess
}

func (s *SessionStore) Delete(localSEID uint64) ([]report.USAReport, error) {
	if localSEID == 0 {
		return nil, errors.New("SessionStore.Delete: invalid localSEID:0")
	}

	// Capacity as int; compare as uint64 to match localSEID type.
	sessionCapacity := len(s.sessions)
	if localSEID > uint64(sessionCapacity) {
		return nil, errors.Errorf(
			"SessionStore.Delete: session not found (localSEID:%#x)",
			localSEID,
		)
	}

	// Safe: 1 <= localSEID <= sessionCapacity guarantees a valid index.
	index := int(localSEID) - 1
	if s.sessions[index] == nil {
		return nil, errors.Errorf(
			"SessionStore.Delete: session not found (localSEID:%#x)",
			localSEID,
		)
	}

	s.sessions[index].log.Infoln("session deleted")
	reports := s.sessions[index].Close()
	s.sessions[index] = nil
	s.freeSEIDs = append(s.freeSEIDs, localSEID)

	return reports, nil
}
