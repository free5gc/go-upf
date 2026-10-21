package nupf_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/upf/EvtExpos"
)

// Uses the generated client version used by free5gc/smf#248, not copies of
// the UPF's JSON structs. No live SMF, PFCP peer, or kernel module is required.
func TestSMFGeneratedClientCreateNotifyDelete(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	logger := logrus.NewEntry(log)
	store := ees.NewSubscriptionStore("")
	aggregator := ees.NewAggregator(store, 10*time.Second, ees.NewNotifier(logger), logger, nil, nil)
	server := httptest.NewUnstartedServer(ees.NewServer(store, aggregator, logger).Handler())
	server.Config.Protocols = ees.Protocols()
	server.Start()
	defer server.Close()
	notifications := make(chan models.Upf_EvtExpos_NotificationData, 1)
	decodeErrors := make(chan error, 1)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var notification models.Upf_EvtExpos_NotificationData
		if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
			decodeErrors <- err
			w.WriteHeader(400)
			return
		}
		notifications <- notification
		w.WriteHeader(204)
	}))
	defer callback.Close()
	config := EvtExpos.NewConfiguration()
	config.SetBasePath(server.URL)
	config.SetRedirectPolicy(openapi.RejectRedirects)
	client := EvtExpos.NewAPIClient(config)
	// Mirrors buildNupfEventExposureRequest: supplementary identifiers accompany
	// the IPv4 target. This UPF profile selects by IPv4, not SUPI/DNN/S-NSSAI.
	body := &models.Upf_EvtExpos_CreateEventSubscription{
		Subscription: &models.Upf_EvtExpos_UpfEventSubscription{
			NfId: "e9445ccb-646e-4a0e-bd88-b4a654410c44",
			EventList: []models.Upf_EvtExpos_UpfEvent{{
				Type:                     models.Upf_EvtExpos_EventType_USER_DATA_USAGE_MEASURES,
				GranularityOfMeasurement: models.Upf_EvtExpos_GranularityOfMeasurement_SESSION,
				MeasurementTypes: []models.Upf_EvtExpos_MeasurementType{
					models.Upf_EvtExpos_MeasurementType_VOLUME_MEASUREMENT,
				},
			}},
			EventNotifyUri:      callback.URL,
			NotifyCorrelationId: "smf-correlation",
			EventReportingMode: &models.Upf_EvtExpos_UpfEventMode{
				Trigger: models.Upf_EvtExpos_UpfEventTrigger_PERIODIC, RepPeriod: 1,
			},
			UeIpAddress: &models.IpAddr{Ipv4Addr: "10.60.0.1"},
			Supi:        "imsi-208930000000001", Dnn: "internet", Snssai: &models.Snssai{Sst: 1, Sd: "010203"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	created, err := client.SubscriptionsCollectionApi.CreateSubscription(ctx,
		&EvtExpos.CreateSubscriptionRequest{RequestBody: body})
	if err != nil {
		t.Fatal(err)
	}
	if created == nil || created.Upf_EvtExpos_CreatedEventSubscription == nil {
		t.Fatal("missing response")
	}
	resource := created.Upf_EvtExpos_CreatedEventSubscription
	if resource.Subscription == nil || resource.SubscriptionId == "" || resource.SubscriptionId != created.Location {
		t.Fatal("response fails SMF Location/subscriptionId validation")
	}
	location, err := url.Parse(resource.SubscriptionId)
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme != base.Scheme || location.Host != base.Host ||
		!strings.HasPrefix(location.Path, "/nupf-ee/v1/ee-subscriptions/") {
		t.Fatal("resource URI fails SMF same-origin validation")
	}
	id := path.Base(location.Path)
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { aggregator.Run(runCtx); close(done) }()
	defer func() { stop(); <-done }()
	aggregator.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{
		report.USAReport{
			URRID: 2, StartTime: time.Now().Add(-time.Second), EndTime: time.Now(),
			VolumMeasure: report.VolumeMeasure{UplinkVolume: 123},
		},
	}}, ees.SessionContext{RemoteSEID: 99, Generation: 1, UeIPv4Addr: "10.60.0.1"})
	select {
	case notification := <-notifications:
		if notification.CorrelationId != "smf-correlation" || len(notification.NotificationItems) != 1 {
			t.Fatalf("unexpected notification: %+v", notification)
		}
		measurement := notification.NotificationItems[0].UserDataUsageMeasurements[0].VolumeMeasurement
		if measurement.TotalVolume != "123 B" || measurement.DlVolume != "0 B" {
			t.Fatalf("invalid TrafficVolume: %+v", measurement)
		}
	case decodeErr := <-decodeErrors:
		t.Fatal(decodeErr)
	case <-ctx.Done():
		t.Fatal("missing notification")
	}
	_, err = client.DefaultApi.DeleteSubscription(ctx, &EvtExpos.DeleteSubscriptionRequest{SubscriptionId: &id})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := store.GetSubscription(id); exists {
		t.Fatal("subscription not deleted")
	}
}
