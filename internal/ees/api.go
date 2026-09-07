// Package ees - UPF Event Exposure Service (EES)
// api.go: minimal REST API for EES subscriptions (create/delete).
//
// Endpoints (MVP):
//   POST   /nupf-ee/v1/ee-subscriptions        -> Create subscription
//   DELETE /nupf-ee/v1/ee-subscriptions/{id}   -> Delete subscription
//
// Scope & constraints (MVP):
// - Only USER_DATA_USAGE_MEASURES + perPduSession are accepted.
// - Mode supports PERIODIC and ON_DEMAND; ON_DEMAND triggers an immediate TickOnce().
// - Uses SMF-provisioned URRs for data collection (no Shadow URR).

package ees

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Server provides the minimal REST API for EES.
type Server struct {
	subscriptionStore *SubscriptionStore
	aggregator        *Aggregator
	logger            *logrus.Entry
	httpServer        *http.Server
}

// NewServer constructs a Server.
func NewServer(
	store *SubscriptionStore,
	aggregator *Aggregator,
	logger *logrus.Entry,
) *Server {
	return &Server{
		subscriptionStore: store,
		aggregator:        aggregator,
		logger:            logger,
	}
}

// Routes registers handlers into the given mux.
func (server *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/nupf-ee/v1/ee-subscriptions", server.handleCreateSubscription)      // POST
	mux.HandleFunc("/nupf-ee/v1/ee-subscriptions/", server.handleDeleteSubscriptionByID) // DELETE /.../{id}
}

// Serve starts an HTTP server on the given listen address.
func (server *Server) Serve(listenAddress string) error {
	mux := http.NewServeMux()
	server.Routes(mux)

	server.logger.Infof("ees api server listening at %s", listenAddress)
	server.httpServer = &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the API server.
func (server *Server) Shutdown(ctx context.Context) error {
	if server.httpServer != nil {
		server.logger.Info("shutting down ees api server")
		return server.httpServer.Shutdown(ctx)
	}
	return nil
}

// ----- Request/Response models -----

type createSubscriptionRequest struct {
	Subscription UpfEventSubscription `json:"subscription"`
	// SupportedFeatures string `json:"supportedFeatures,omitempty"` // Not implemented yet
}

type UpfEventSubscription struct {
	NfID                string       `json:"nfId"`
	EventList           []UpfEvent   `json:"eventList"`
	EventNotifyURI      string       `json:"eventNotifyUri"`
	NotifyCorrelationID string       `json:"notifyCorrelationId"`
	EventReportingMode  UpfEventMode `json:"eventReportingMode"`

	// Targeting: choose one
	UeIPAddress string `json:"ueIpAddress,omitempty"`
	AnyUE       bool   `json:"anyUe,omitempty"`
}

type UpfEvent struct {
	Type             string   `json:"type"`
	MeasurementTypes []string `json:"measurementTypes,omitempty"`
	// TS 29.564: Required when type=USER_DATA_USAGE_MEASURES
	GranularityOfMeasurement string `json:"granularityOfMeasurement,omitempty"`
	// PER_SESSION, PER_APPLICATION, PER_FLOW
	AppIds []string `json:"appIds,omitempty"`
	// Required for PER_APPLICATION
	TrafficFilters []FlowInformation `json:"trafficFilters,omitempty"`
	// Required for PER_FLOW
}

type UpfEventMode struct {
	Trigger      string `json:"trigger"`                // "PERIODIC" | "ONE_TIME"
	ReportPeriod int    `json:"reportPeriod,omitempty"` // Seconds
}

type createSubscriptionResponse struct {
	Subscription   UpfEventSubscription `json:"subscription"`
	SubscriptionID string               `json:"subscriptionId"`
	// ReportList     []NotificationItem   `json:"reportList,omitempty"` // Not implemented in immediate response yet
}

// ----- Handlers -----

// handleCreateSubscription handles POST /nupf-ee/v1/ee-subscriptions
func (server *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var inboundRequest createSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&inboundRequest); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}

	subscriptionCandidate, validationErr := server.validateAndMapRequest(inboundRequest)
	if validationErr != nil {
		server.logger.Warnf("subscription validation failed: %v", validationErr)
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	id, err := server.subscriptionStore.CreateSubscription(subscriptionCandidate)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrInvalidSubscription) {
			status = http.StatusBadRequest
		}
		server.logger.Warnf("subscription store failed: %v", err)
		http.Error(w, err.Error(), status)
		return
	}
	server.logger.Infof("ees subscription created: id=%s nfId=%s trigger=%s",
		id, inboundRequest.Subscription.NfID, inboundRequest.Subscription.EventReportingMode.Trigger)

	// If Mode is ON_DEMAND, trigger an immediate tick in the aggregator.
	if subscriptionCandidate.Mode == ModeOnDemand && server.aggregator != nil {
		server.logger.Infof("ees immediate tick triggered for subscriptionId=%s", id)
		go func() {
			if _, tickErr := server.aggregator.TickOnce(context.Background()); tickErr != nil {
				server.logger.Warnf("ees on-demand immediate tick failed for subscriptionId=%s: %v", id, tickErr)
			}
		}()
	}

	w.Header().Set("Location", "/nupf-ee/v1/ee-subscriptions/"+id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if encodeErr := json.NewEncoder(w).Encode(createSubscriptionResponse{
		Subscription:   inboundRequest.Subscription,
		SubscriptionID: id,
	}); encodeErr != nil {
		server.logger.Errorf("failed to encode response: %v", encodeErr)
	}
}

// handleDeleteSubscriptionByID handles DELETE /nupf-ee/v1/ee-subscriptions/{id}
func (server *Server) handleDeleteSubscriptionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimSuffix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[len(parts)-1]
	if id == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := server.subscriptionStore.DeleteSubscription(id); err == nil {
		server.logger.Infof("ees subscription deleted: id=%s", id)
		w.WriteHeader(http.StatusNoContent)
	} else {
		server.logger.Warnf("ees subscription delete failed: not found: id=%s", id)
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// ----- Internal Helpers -----

func (server *Server) validateAndMapRequest(req createSubscriptionRequest) (*Subscription, error) {
	sub := req.Subscription
	if len(sub.EventList) == 0 {
		return nil, errors.New("eventList must not be empty")
	}

	// MVP: Only support the first event for now
	e := sub.EventList[0]
	if e.Type != string(EventUserDataUsageMeasures) {
		return nil, fmt.Errorf("unsupported event type: %s", e.Type)
	}

	// MVP: Only support PER_SESSION granularity
	if e.GranularityOfMeasurement != string(GranularityPerSession) {
		return nil, fmt.Errorf("unsupported granularity: %s (MVP only supports PER_SESSION)", e.GranularityOfMeasurement)
	}

	var mode Mode
	switch strings.ToUpper(sub.EventReportingMode.Trigger) {
	case "PERIODIC":
		mode = ModePeriodic
	case "ONE_TIME":
		mode = ModeOnDemand
	default:
		return nil, fmt.Errorf("unsupported trigger: %s", sub.EventReportingMode.Trigger)
	}

	mTypes := make([]MeasurementType, 0, len(e.MeasurementTypes))
	for _, mt := range e.MeasurementTypes {
		mtStr := MeasurementType(strings.ToUpper(mt))
		if mtStr != MeasureVolume && mtStr != MeasureThroughput && mtStr != MeasureAppInfo {
			return nil, fmt.Errorf("unsupported measurementType: %s", mt)
		}
		mTypes = append(mTypes, mtStr)
	}

	if sub.AnyUE && sub.UeIPAddress != "" {
		return nil, errors.New("cannot specify both anyUe and ueIpAddress")
	}
	if !sub.AnyUE && sub.UeIPAddress == "" {
		return nil, errors.New("must specify either anyUe or ueIpAddress")
	}

	return &Subscription{
		Event:               EventType(e.Type),
		NotifURI:            sub.EventNotifyURI,
		NotifyCorrelationID: sub.NotifyCorrelationID,
		NfID:                sub.NfID,
		Granularity:         Granularity(e.GranularityOfMeasurement),
		Mode:                mode,
		PeriodSec:           sub.EventReportingMode.ReportPeriod,
		MeasurementTypes:    mTypes,
		Target: TargetScope{
			UeIPAddress: sub.UeIPAddress,
			AnyUE:       sub.AnyUE,
		},
		Snapshots: make(map[SessionKey]Counters),
	}, nil
}
