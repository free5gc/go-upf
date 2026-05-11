package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

// PfcpInterface defines the subset of PfcpServer that the exposure server needs.
type PfcpInterface interface {
	AddMonitoringURR(lSeid uint64, urrid uint32, repPeriod time.Duration) error
	RemoveMonitoringURR(lSeid uint64, urrid uint32) error
}

// NodeInterface gives access to sessions for subscription matching.
type NodeInterface interface {
	// GetAllSessions returns a snapshot of all active sessions.
	// Each entry exposes at minimum: LocalID, UeIpAddr, Dnn.
	GetAllSessions() []SessionInfo
}

// SessionInfo is the minimal session info the exposure server needs.
type SessionInfo struct {
	LocalID        uint64
	UeIpAddr       net.IP
	Dnn            string
	ExistingURRIDs map[uint32]struct{}
}

// subscriptionRecord tracks the internal state of one Nupf_EventExposure subscription.
type subscriptionRecord struct {
	subID string
	sub   UpfEventSubscription
	// sessionURRs maps localSeid → monitoring URRID allocated for that session.
	sessionURRs map[uint64]uint32
}

// Server is the Nupf_EventExposure HTTP server (3GPP TS 29.564).
// It creates and manages monitoring URRs on PFCP sessions for matched UEs.
type Server struct {
	listenAddr string
	pfcp       PfcpInterface
	node       NodeInterface

	mu   sync.RWMutex
	subs map[string]*subscriptionRecord // key: subscriptionId

	httpServer *http.Server
}

// NewServer creates a new exposure Server.
func NewServer(listenAddr string, pfcp PfcpInterface, node NodeInterface) *Server {
	s := &Server{
		listenAddr: listenAddr,
		pfcp:       pfcp,
		node:       node,
		subs:       make(map[string]*subscriptionRecord),
	}
	return s
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	v1 := router.Group("/nupf-ee/v1")
	v1.POST("/ee-subscriptions", s.handleCreateSubscription)
	v1.DELETE("/ee-subscriptions/:subscriptionId", s.handleDeleteSubscription)
	v1.PATCH("/ee-subscriptions/:subscriptionId", s.handleModifySubscription)

	srv := &http.Server{
		Addr:    s.listenAddr,
		Handler: router,
	}
	s.httpServer = srv

	logger.ExposureLog.Infof("Nupf_EventExposure server listening on %s", s.listenAddr)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// HandleReport is called by the ReportMultiplexer for each SessReport.
// It returns true if the report was fully consumed (belongs to a monitoring URR).
func (s *Server) HandleReport(sr report.SessReport) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	consumed := false
	for _, rec := range s.subs {
		monURRID, ok := rec.sessionURRs[sr.SEID]
		if !ok {
			continue
		}
		for _, r := range sr.Reports {
			usar, isUSA := r.(report.USAReport)
			if !isUSA || usar.URRID != monURRID {
				continue
			}
			// Build and send notification
			s.sendNotification(rec, sr.SEID, usar)
			consumed = true
		}
	}
	return consumed
}

// sendNotification sends a Nupf_EventExposure notification to the subscriber's URI.
func (s *Server) sendNotification(rec *subscriptionRecord, lSeid uint64, usar report.USAReport) {
	item := buildNotificationItem(rec.sub, usar)
	notif := NotificationData{
		NotifCorrId:       rec.sub.NotifCorrId,
		NotificationItems: []NotificationItem{item},
	}

	body, err := json.Marshal(notif)
	if err != nil {
		logger.ExposureLog.Warnf("sendNotification marshal error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rec.sub.EventNotifyUri, bytes.NewReader(body))
	if err != nil {
		logger.ExposureLog.Warnf("sendNotification create request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.ExposureLog.Warnf("sendNotification POST to %s error: %v", rec.sub.EventNotifyUri, err)
		return
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			logger.ExposureLog.Warnf("failed to close response body: %v", errClose)
		}
	}()
	logger.ExposureLog.Infof("Sent notification to %s for sub %s, status %d",
		rec.sub.EventNotifyUri, rec.subID, resp.StatusCode)
}

func buildNotificationItem(sub UpfEventSubscription, usar report.USAReport) NotificationItem {
	item := NotificationItem{
		SourceUeIpAddress: sub.UeIpAddress,
		TimeStamp:         time.Now().UTC(),
	}
	// Determine primary event type from subscription
	if len(sub.EventList) > 0 {
		item.EventType = sub.EventList[0].Type
	} else {
		item.EventType = EventTypeUserDataUsageMeasures
	}

	vol := usar.VolumMeasure
	totalVol := vol.TotalVolume
	ulVol := vol.UplinkVolume
	dlVol := vol.DownlinkVolume
	item.UsageData = []UserDataUsageMeasurements{
		{
			VolumeMeasurement: &VolumeMeasurement{
				TotalVolume:    &totalVol,
				UplinkVolume:   &ulVol,
				DownlinkVolume: &dlVol,
			},
		},
	}
	return item
}

// --- HTTP handlers ---

// handleCreateSubscription handles POST /nupf-ee/v1/ee-subscriptions.
func (s *Server) handleCreateSubscription(c *gin.Context) {
	s.TestHandleCreate(c)
}

// TestHandleCreate is exported for test router wiring.
func (s *Server) TestHandleCreate(c *gin.Context) {
	var req CreateEventSubscription
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"cause": err.Error()})
		return
	}

	created, status, err := s.CreateSubscription(req)
	if err != nil {
		c.JSON(status, gin.H{"cause": err.Error()})
		return
	}

	locationURI := fmt.Sprintf("%s/nupf-ee/v1/ee-subscriptions/%s",
		c.Request.Host, created.SubscriptionId)
	c.Header("Location", locationURI)
	c.JSON(http.StatusCreated, created)
}

// handleDeleteSubscription handles DELETE /nupf-ee/v1/ee-subscriptions/{subscriptionId}.
func (s *Server) handleDeleteSubscription(c *gin.Context) {
	s.TestHandleDelete(c)
}

// TestHandleDelete is exported for test router wiring.
func (s *Server) TestHandleDelete(c *gin.Context) {
	subID := c.Param("subscriptionId")
	status, err := s.DeleteSubscription(subID)
	if err != nil {
		c.JSON(status, gin.H{"cause": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// handleModifySubscription handles PATCH /nupf-ee/v1/ee-subscriptions/{subscriptionId}.
func (s *Server) handleModifySubscription(c *gin.Context) {
	s.TestHandleModify(c)
}

// TestHandleModify is exported for test router wiring.
func (s *Server) TestHandleModify(c *gin.Context) {
	subID := c.Param("subscriptionId")
	var req ModifySubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"cause": err.Error()})
		return
	}

	modified, status, err := s.modifySubscription(subID, req)
	if err != nil {
		c.JSON(status, gin.H{"cause": err.Error()})
		return
	}
	c.JSON(http.StatusOK, modified)
}

// --- Subscription logic ---

// CreateSubscription implements subscription creation logic for both HTTP handler and tests.
func (s *Server) CreateSubscription(req CreateEventSubscription) (CreatedEventSubscription, int, error) {
	sub := req.Subscription
	sessions := s.node.GetAllSessions()

	// Find sessions that match the subscription criteria
	matched := matchingSessions(sessions, sub)
	if len(matched) == 0 {
		return CreatedEventSubscription{}, http.StatusNotFound,
			fmt.Errorf("no matching PDU sessions found")
	}

	repPeriod := repPeriodFromMode(sub.EventMode)
	subID := uuid.New().String()
	rec := &subscriptionRecord{
		subID:       subID,
		sub:         sub,
		sessionURRs: make(map[uint64]uint32),
	}

	for _, sess := range matched {
		urrid := allocateURRID(sess.ExistingURRIDs)
		if err := s.pfcp.AddMonitoringURR(sess.LocalID, urrid, repPeriod); err != nil {
			logger.ExposureLog.Warnf("AddMonitoringURR lSeid=%d urrid=%d: %v", sess.LocalID, urrid, err)
			continue
		}
		rec.sessionURRs[sess.LocalID] = urrid
	}

	if len(rec.sessionURRs) == 0 {
		return CreatedEventSubscription{}, http.StatusInternalServerError,
			fmt.Errorf("failed to add monitoring URR to any session")
	}

	s.mu.Lock()
	s.subs[subID] = rec
	s.mu.Unlock()

	return CreatedEventSubscription{
		SubscriptionId: subID,
		Subscription:   sub,
	}, http.StatusCreated, nil
}

// DeleteSubscription implements subscription deletion logic for both HTTP handler and tests.
func (s *Server) DeleteSubscription(subID string) (int, error) {
	s.mu.Lock()
	rec, ok := s.subs[subID]
	if !ok {
		s.mu.Unlock()
		return http.StatusNotFound, fmt.Errorf("subscription %s not found", subID)
	}
	delete(s.subs, subID)
	s.mu.Unlock()

	for lSeid, urrid := range rec.sessionURRs {
		if err := s.pfcp.RemoveMonitoringURR(lSeid, urrid); err != nil {
			logger.ExposureLog.Warnf("RemoveMonitoringURR lSeid=%d urrid=%d: %v", lSeid, urrid, err)
		}
	}
	return http.StatusNoContent, nil
}

func (s *Server) modifySubscription(subID string, req ModifySubscriptionRequest) (UpfEventSubscription, int, error) {
	newSub := req.Subscription
	matches := matchingSessions(s.node.GetAllSessions(), newSub)
	if len(matches) == 0 {
		return UpfEventSubscription{}, http.StatusNotFound, errors.New("no matching PDU session for subscription")
	}

	repPeriod := repPeriodFromMode(newSub.EventMode)
	newSessionURRs := make(map[uint64]uint32, len(matches))

	s.mu.Lock()
	rec, ok := s.subs[subID]
	if !ok {
		s.mu.Unlock()
		return UpfEventSubscription{}, http.StatusNotFound, fmt.Errorf("subscription %s not found", subID)
	}
	oldSessionURRs := make(map[uint64]uint32, len(rec.sessionURRs))
	for lSeid, urrid := range rec.sessionURRs {
		oldSessionURRs[lSeid] = urrid
	}
	s.mu.Unlock()

	for _, sess := range matches {
		existing := make(map[uint32]struct{}, len(sess.ExistingURRIDs)+1)
		for id := range sess.ExistingURRIDs {
			existing[id] = struct{}{}
		}
		if oldURRID, oldOK := oldSessionURRs[sess.LocalID]; oldOK {
			existing[oldURRID] = struct{}{}
		}
		urrid := allocateURRID(existing)
		if err := s.pfcp.AddMonitoringURR(sess.LocalID, urrid, repPeriod); err != nil {
			logger.ExposureLog.Warnf("Modify AddMonitoringURR lSeid=%d urrid=%d: %v", sess.LocalID, urrid, err)
			continue
		}
		newSessionURRs[sess.LocalID] = urrid
	}
	if len(newSessionURRs) == 0 {
		return UpfEventSubscription{}, http.StatusInternalServerError,
			errors.New("failed to add monitoring URR to any session")
	}

	for lSeid, urrid := range oldSessionURRs {
		if err := s.pfcp.RemoveMonitoringURR(lSeid, urrid); err != nil {
			logger.ExposureLog.Warnf("Modify RemoveMonitoringURR lSeid=%d urrid=%d: %v", lSeid, urrid, err)
		}
	}

	s.mu.Lock()
	rec, ok = s.subs[subID]
	if !ok {
		s.mu.Unlock()
		for lSeid, urrid := range newSessionURRs {
			if err := s.pfcp.RemoveMonitoringURR(lSeid, urrid); err != nil {
				logger.ExposureLog.Warnf("rollback RemoveMonitoringURR lSeid=%d urrid=%d: %v", lSeid, urrid, err)
			}
		}
		return UpfEventSubscription{}, http.StatusNotFound, fmt.Errorf("subscription %s not found", subID)
	}
	rec.sub = newSub
	rec.sessionURRs = newSessionURRs
	s.mu.Unlock()

	return newSub, http.StatusOK, nil
}

// matchingSessions returns all sessions that match the subscription criteria.
func matchingSessions(sessions []SessionInfo, sub UpfEventSubscription) []SessionInfo {
	var result []SessionInfo
	for _, sess := range sessions {
		if sub.AnyUe {
			result = append(result, sess)
			continue
		}
		if sub.UeIpAddress != nil && sess.UeIpAddr != nil && sub.UeIpAddress.Equal(sess.UeIpAddr) {
			result = append(result, sess)
			continue
		}
		if sub.Dnn != "" && sub.Dnn == sess.Dnn {
			result = append(result, sess)
			continue
		}
	}
	return result
}

// allocateURRID finds an unused URR ID starting from UpfMonitoringURRIDBase.
// The monitoring range is 0xF0000001..0xFFFFFFFF to avoid collisions with SMF-allocated URRs.
const monitoringURRIDBase uint32 = 0xF0000001

func allocateURRID(existing map[uint32]struct{}) uint32 {
	for id := monitoringURRIDBase; id != 0; id++ { // wraps around on overflow
		if _, used := existing[id]; !used {
			return id
		}
	}
	// Fallback: should never happen with a 268M range
	return monitoringURRIDBase
}

// repPeriodFromMode extracts the reporting period from UpfEventMode.
// Returns 60s as default if no period is specified.
func repPeriodFromMode(mode UpfEventMode) time.Duration {
	if mode.RepPeriod != nil && *mode.RepPeriod > 0 {
		return time.Duration(*mode.RepPeriod) * time.Second
	}
	return 60 * time.Second
}
