// Package ees - UPF Event Exposure Service (EES)
// api.go: minimal REST API for EES subscriptions (create/delete).
//
// Endpoints (MVP):
//   POST   /nupf-ee/v1/ee-subscriptions        -> Create subscription
//   DELETE /nupf-ee/v1/ee-subscriptions/{id}   -> Delete subscription
//
// Scope & constraints (MVP):
// - Only USER_DATA_USAGE_MEASURES + perPduSession are accepted.
// - PERIODIC and ONE_TIME wait for real measurements; no synthetic zero reports.
// - Uses SMF-provisioned URRs for data collection (no Shadow URR).

package ees

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Server provides the minimal REST API for EES.
type Server struct {
	subscriptionStore *SubscriptionStore
	logger            *logrus.Entry
	httpServer        *http.Server
}

// NewServer constructs a Server.
func NewServer(store *SubscriptionStore, logger *logrus.Entry) *Server {
	server := &Server{
		subscriptionStore: store,
		logger:            logger,
	}
	server.httpServer = &http.Server{
		Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, Protocols: Protocols(),
	}
	return server
}

// Routes registers handlers into the given mux.
func (server *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/nupf-ee/v1/ee-subscriptions", server.handleCreateSubscription)      // POST
	mux.HandleFunc("/nupf-ee/v1/ee-subscriptions/", server.handleDeleteSubscriptionByID) // DELETE /.../{id}
}

// Protocols enables HTTP/1.1 and HTTP/2 with prior knowledge (h2c), as used by
// the free5GC generated SBI client on an http:// API root.
func Protocols() *http.Protocols {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	return protocols
}

// Handler returns the EES routes. Serve it with Protocols() for h2c clients.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	server.Routes(mux)
	return mux
}

// Serve starts an HTTP server on the given listen address.
func (server *Server) Serve(listenAddress string) error {
	server.logger.Infof("ees api server listening at %s", listenAddress)
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddress)
	if err != nil {
		return err
	}
	if err := server.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
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
	UeIPAddress *IPAddr `json:"ueIpAddress,omitempty"`
	AnyUE       bool    `json:"anyUe,omitempty"`
}

// IPv4 is the supported target in this single-UPF MVP. Other IpAddr forms
// are decoded so they can be explicitly rejected rather than silently ignored.
type IPAddr struct {
	IPv4Addr   string `json:"ipv4Addr,omitempty"`
	IPv6Addr   string `json:"ipv6Addr,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
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
	Trigger      string `json:"trigger"`             // "PERIODIC" | "ONE_TIME"
	ReportPeriod int    `json:"repPeriod,omitempty"` // Seconds (TS 29.564)
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
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	// Preserve forward-compatible decoding (the SMF also sends supplementary
	// identifiers such as SUPI). This MVP selects targets by UE IPv4.
	if err := decoder.Decode(&inboundRequest); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "request must contain exactly one JSON object", http.StatusBadRequest)
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

	// Do not trust forwarded headers from arbitrary clients. Deployments using
	// TLS termination must preserve the externally advertised scheme/authority.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	resourceURI := (&url.URL{Scheme: scheme, Host: r.Host, Path: "/nupf-ee/v1/ee-subscriptions/" + id}).String()
	w.Header().Set("Location", resourceURI)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if encodeErr := json.NewEncoder(w).Encode(createSubscriptionResponse{
		Subscription:   inboundRequest.Subscription,
		SubscriptionID: resourceURI,
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

	const prefix = "/nupf-ee/v1/ee-subscriptions/"
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if !strings.HasPrefix(r.URL.Path, prefix) || id == "" || strings.Contains(id, "/") {
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
	if len(sub.EventList) != 1 {
		return nil, errors.New("exactly one event is supported")
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
	if len(e.AppIds) != 0 || len(e.TrafficFilters) != 0 {
		return nil, errors.New("PER_SESSION cannot include appIds or trafficFilters")
	}
	if len(e.MeasurementTypes) == 0 {
		return nil, errors.New("measurementTypes must not be empty")
	}
	notifyURL, err := url.Parse(sub.EventNotifyURI)
	if err != nil || notifyURL.Host == "" || (notifyURL.Scheme != "http" && notifyURL.Scheme != "https") {
		return nil, errors.New("eventNotifyUri must be an absolute HTTP(S) URI")
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
		if mtStr != MeasureVolume && mtStr != MeasureThroughput {
			return nil, fmt.Errorf("unsupported measurementType: %s", mt)
		}
		mTypes = append(mTypes, mtStr)
	}

	if sub.AnyUE && sub.UeIPAddress != nil {
		return nil, errors.New("cannot specify both anyUe and ueIpAddress")
	}
	if !sub.AnyUE && sub.UeIPAddress == nil {
		return nil, errors.New("must specify either anyUe or ueIpAddress")
	}
	var ueIP string
	if sub.UeIPAddress != nil {
		ip := net.ParseIP(sub.UeIPAddress.IPv4Addr)
		if ip == nil || ip.To4() == nil || sub.UeIPAddress.IPv6Addr != "" || sub.UeIPAddress.IPv6Prefix != "" {
			return nil, errors.New("ueIpAddress must contain a supported IPv4 address only")
		}
		ueIP = ip.To4().String()
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
			UeIPAddress: ueIP,
			AnyUE:       sub.AnyUE,
		},
	}, nil
}
