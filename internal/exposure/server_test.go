package exposure_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/exposure"
	"github.com/free5gc/go-upf/internal/report"
)

// --- Fakes ---

type fakePfcp struct {
	mu      sync.Mutex
	added   []addCall
	removed []removeCall
	addErr  error
}

type addCall struct {
	lSeid     uint64
	urrid     uint32
	repPeriod time.Duration
}

type removeCall struct {
	lSeid uint64
	urrid uint32
}

func (f *fakePfcp) AddMonitoringURR(lSeid uint64, urrid uint32, repPeriod time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, addCall{lSeid, urrid, repPeriod})
	return f.addErr
}

func (f *fakePfcp) RemoveMonitoringURR(lSeid uint64, urrid uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, removeCall{lSeid, urrid})
	return nil
}

type fakeNode struct {
	sessions []exposure.SessionInfo
}

func (n *fakeNode) GetAllSessions() []exposure.SessionInfo {
	return n.sessions
}

// --- Test helpers ---

func newTestServer(pfcp exposure.PfcpInterface, node exposure.NodeInterface) *exposure.Server {
	return exposure.NewServer("", pfcp, node)
}

// buildRouter creates a test gin router backed by a Server (for httptest usage).
func buildRouter(srv *exposure.Server) http.Handler {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/nupf-ee/v1/ee-subscriptions", srv.TestHandleCreate)
	r.DELETE("/nupf-ee/v1/ee-subscriptions/:subscriptionId", srv.TestHandleDelete)
	r.PATCH("/nupf-ee/v1/ee-subscriptions/:subscriptionId", srv.TestHandleModify)
	return r
}

// --- Tests ---

func TestCreateSubscription_MatchByUeIP(t *testing.T) {
	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	repPeriod := int32(30)
	req := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-1",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic, RepPeriod: &repPeriod},
			UeIpAddress:    ueIP,
		},
	}

	created, status, err := srv.CreateSubscription(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, status)
	assert.NotEmpty(t, created.SubscriptionId)

	pfcpFake.mu.Lock()
	defer pfcpFake.mu.Unlock()
	require.Len(t, pfcpFake.added, 1)
	assert.Equal(t, uint64(1), pfcpFake.added[0].lSeid)
	assert.Equal(t, 30*time.Second, pfcpFake.added[0].repPeriod)
}

func TestCreateSubscription_AnyUe(t *testing.T) {
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: net.ParseIP("10.60.0.1").To4(), ExistingURRIDs: map[uint32]struct{}{}},
			{LocalID: 2, UeIpAddr: net.ParseIP("10.60.0.2").To4(), ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	req := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-2",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			AnyUe:          true,
		},
	}

	created, status, err := srv.CreateSubscription(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, status)
	assert.NotEmpty(t, created.SubscriptionId)

	pfcpFake.mu.Lock()
	defer pfcpFake.mu.Unlock()
	assert.Len(t, pfcpFake.added, 2)
}

func TestCreateSubscription_NoMatch(t *testing.T) {
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: net.ParseIP("10.60.0.1").To4(), ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	req := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-3",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			UeIpAddress:    net.ParseIP("10.60.99.99").To4(),
		},
	}

	_, status, err := srv.CreateSubscription(req)
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, status)
}

func TestDeleteSubscription(t *testing.T) {
	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	req := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-4",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			UeIpAddress:    ueIP,
		},
	}

	created, _, err := srv.CreateSubscription(req)
	require.NoError(t, err)

	status, err := srv.DeleteSubscription(created.SubscriptionId)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, status)

	pfcpFake.mu.Lock()
	defer pfcpFake.mu.Unlock()
	require.Len(t, pfcpFake.removed, 1)
	assert.Equal(t, uint64(1), pfcpFake.removed[0].lSeid)
}

func TestDeleteSubscription_NotFound(t *testing.T) {
	srv := newTestServer(&fakePfcp{}, &fakeNode{})
	status, err := srv.DeleteSubscription("nonexistent-id")
	assert.Error(t, err)
	assert.Equal(t, http.StatusNotFound, status)
}

func TestModifySubscription_ReprogramsMonitoringURR(t *testing.T) {
	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	initialPeriod := int32(30)
	created, _, err := srv.CreateSubscription(exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-mod-before",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic, RepPeriod: &initialPeriod},
			UeIpAddress:    ueIP,
		},
	})
	require.NoError(t, err)

	pfcpFake.mu.Lock()
	require.Len(t, pfcpFake.added, 1)
	oldAdd := pfcpFake.added[0]
	pfcpFake.mu.Unlock()

	updatedPeriod := int32(10)
	bodyBytes, err := json.Marshal(exposure.ModifySubscriptionRequest{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/new-notif",
			NotifCorrId:    "corr-mod-after",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic, RepPeriod: &updatedPeriod},
			UeIpAddress:    ueIP,
		},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router := buildRouter(srv)
	httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodPatch,
		"/nupf-ee/v1/ee-subscriptions/"+created.SubscriptionId,
		bytes.NewReader(bodyBytes))
	httpReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusOK, w.Code)
	var modified exposure.UpfEventSubscription
	err = json.Unmarshal(w.Body.Bytes(), &modified)
	require.NoError(t, err)
	assert.Equal(t, "corr-mod-after", modified.NotifCorrId)

	pfcpFake.mu.Lock()
	defer pfcpFake.mu.Unlock()
	require.Len(t, pfcpFake.added, 2)
	require.Len(t, pfcpFake.removed, 1)
	assert.Equal(t, uint64(1), pfcpFake.added[1].lSeid)
	assert.Equal(t, 10*time.Second, pfcpFake.added[1].repPeriod)
	assert.NotEqual(t, oldAdd.urrid, pfcpFake.added[1].urrid)
	assert.Equal(t, oldAdd.urrid, pfcpFake.removed[0].urrid)
}

func TestModifySubscription_NoMatch(t *testing.T) {
	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	created, _, err := srv.CreateSubscription(exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-mod-before",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			UeIpAddress:    ueIP,
		},
	})
	require.NoError(t, err)

	bodyBytes, err := json.Marshal(exposure.ModifySubscriptionRequest{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/new-notif",
			NotifCorrId:    "corr-mod-after",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			UeIpAddress:    net.ParseIP("10.60.99.99").To4(),
		},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router := buildRouter(srv)
	httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodPatch,
		"/nupf-ee/v1/ee-subscriptions/"+created.SubscriptionId,
		bytes.NewReader(bodyBytes))
	httpReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusNotFound, w.Code)

	pfcpFake.mu.Lock()
	defer pfcpFake.mu.Unlock()
	assert.Len(t, pfcpFake.added, 1)
	assert.Len(t, pfcpFake.removed, 0)
}

func TestHandleReport_ConsumesMonitoringURR(t *testing.T) {
	// We need a notification receiver
	notifReceived := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notifReceived <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	req := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: ts.URL + "/notif",
			NotifCorrId:    "corr-5",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			UeIpAddress:    ueIP,
		},
	}

	created, _, err := srv.CreateSubscription(req)
	require.NoError(t, err)
	_ = created

	// Get the URRID that was allocated
	pfcpFake.mu.Lock()
	require.Len(t, pfcpFake.added, 1)
	allocatedURRID := pfcpFake.added[0].urrid
	pfcpFake.mu.Unlock()

	// Simulate a PFCP usage report for the monitoring URR
	sr := report.SessReport{
		SEID: 1,
		Reports: []report.Report{
			report.USAReport{
				URRID: allocatedURRID,
				VolumMeasure: report.VolumeMeasure{
					TotalVolume:    1000,
					UplinkVolume:   600,
					DownlinkVolume: 400,
				},
			},
		},
	}

	consumed := srv.HandleReport(sr)
	assert.True(t, consumed)

	select {
	case <-notifReceived:
		// Notification was sent
	case <-time.After(3 * time.Second):
		t.Fatal("expected notification within 3 seconds")
	}
}

func TestHTTPCreateSubscription(t *testing.T) {
	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	repPeriod := int32(60)
	body := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-6",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic, RepPeriod: &repPeriod},
			UeIpAddress:    ueIP,
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router := buildRouter(srv)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/nupf-ee/v1/ee-subscriptions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotEmpty(t, w.Header().Get("Location"))

	var resp exposure.CreatedEventSubscription
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.SubscriptionId)
}

func TestHTTPDeleteSubscription(t *testing.T) {
	ueIP := net.ParseIP("10.60.0.1").To4()
	node := &fakeNode{
		sessions: []exposure.SessionInfo{
			{LocalID: 1, UeIpAddr: ueIP, ExistingURRIDs: map[uint32]struct{}{}},
		},
	}
	pfcpFake := &fakePfcp{}
	srv := newTestServer(pfcpFake, node)

	// Create first
	req := exposure.CreateEventSubscription{
		Subscription: exposure.UpfEventSubscription{
			EventNotifyUri: "http://localhost:9999/notif",
			NotifCorrId:    "corr-7",
			EventList:      []exposure.UpfEvent{{Type: exposure.EventTypeUserDataUsageMeasures}},
			EventMode:      exposure.UpfEventMode{Trigger: exposure.TriggerPeriodic},
			UeIpAddress:    ueIP,
		},
	}
	created, _, err := srv.CreateSubscription(req)
	require.NoError(t, err)

	// Delete via HTTP
	w := httptest.NewRecorder()
	router := buildRouter(srv)
	httpReq := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
		"/nupf-ee/v1/ee-subscriptions/"+created.SubscriptionId, nil)
	router.ServeHTTP(w, httpReq)

	assert.Equal(t, http.StatusNoContent, w.Code)
}
