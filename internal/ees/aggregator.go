package ees

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/report"
)

// SingleUPFMAQEURRID is the free5GC single-UPF, after-QoS measurement rule.
// It is session-scoped, not a global counter. ULCL and arbitrary SMF URR
// allocations are outside this MVP; do not sum all URRs (they may overlap).
const SingleUPFMAQEURRID uint32 = 2

// Aggregator buffers real measurements and schedules each subscription
// independently. It never manufactures measurements for an empty buffer.
type Aggregator struct {
	subscriptionStore *SubscriptionStore
	notifier          *Notifier
	logger            *logrus.Entry
	// mu guards the per-subscription scheduling state below.
	mu           sync.Mutex
	reportBuffer map[string]map[SessionKey]*UsageMeasures // pending usage per subscription
	inFlight     map[string]bool                          // a notification is being sent
	retryAt      map[string]time.Time                     // earliest retry after a failed send
	wake         chan struct{}
	workers      sync.WaitGroup
}

func NewAggregator(store *SubscriptionStore, notifier *Notifier, logger *logrus.Entry) *Aggregator {
	return &Aggregator{
		subscriptionStore: store, notifier: notifier, logger: logger,
		reportBuffer: make(map[string]map[SessionKey]*UsageMeasures),
		inFlight:     make(map[string]bool), retryAt: make(map[string]time.Time),
		wake: make(chan struct{}, 1),
	}
}

func (a *Aggregator) signal() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// Run launches at most one notification per subscription at a time. A slow
// subscriber does not delay other subscriptions or the scheduler.
func (a *Aggregator) Run(ctx context.Context) {
	defer a.workers.Wait()
	for ctx.Err() == nil {
		_, delay := a.dispatch(ctx)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
		case <-a.wake:
		case <-a.subscriptionStore.changed:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// TickOnce is a synchronous drain of currently due subscriptions, useful for
// tests and explicit callers. Run uses the same dispatch without waiting.
func (a *Aggregator) TickOnce(ctx context.Context) (int, error) {
	results, _ := a.dispatch(ctx)
	n := 0
	for _, done := range results {
		select {
		case ok := <-done:
			if ok {
				n++
			}
		case <-ctx.Done():
			return n, ctx.Err()
		}
	}
	return n, ctx.Err()
}

func (a *Aggregator) dispatch(ctx context.Context) ([]<-chan bool, time.Duration) {
	var results []<-chan bool
	delay := time.Hour
	if ctx.Err() != nil {
		return results, delay
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for id := range a.reportBuffer {
		if _, exists := a.subscriptionStore.GetSubscription(id); !exists {
			delete(a.reportBuffer, id)
			delete(a.retryAt, id)
		}
	}
	for _, sub := range a.subscriptionStore.AllSubscriptions() {
		batch := a.reportBuffer[sub.ID]
		if a.inFlight[sub.ID] || len(batch) == 0 {
			continue
		}
		sub.mu.RLock()
		due := periodicDue(sub.LastNotify, time.Duration(sub.PeriodSec)*time.Second, batch, now)
		if sub.Mode == ModeOnDemand {
			due = now
		}
		sub.mu.RUnlock()
		if retry := a.retryAt[sub.ID]; retry.After(due) {
			due = retry
		}
		if due.After(now) {
			if remaining := due.Sub(now); remaining < delay {
				delay = remaining
			}
			continue
		}
		delete(a.reportBuffer, sub.ID)
		a.inFlight[sub.ID] = true
		done := make(chan bool, 1)
		results = append(results, done)
		a.workers.Add(1)
		go func(sub *Subscription, batch map[SessionKey]*UsageMeasures) {
			defer a.workers.Done()
			measures := make([]UsageMeasures, 0, len(batch))
			for _, m := range batch {
				computeThroughputIfPossible(m)
				measures = append(measures, *m)
			}
			err := a.notifier.NotifyContext(ctx, sub, measures)
			a.mu.Lock()
			_, exists := a.subscriptionStore.GetSubscription(sub.ID)
			if err != nil && exists {
				if a.reportBuffer[sub.ID] == nil {
					a.reportBuffer[sub.ID] = make(map[SessionKey]*UsageMeasures)
				}
				for _, m := range batch {
					mergeMeasure(a.reportBuffer[sub.ID], m)
				}
				a.retryAt[sub.ID] = time.Now().Add(time.Second)
				a.logger.WithError(err).Warn("ees notification failed; retaining measurements")
			} else {
				delete(a.retryAt, sub.ID)
				if err == nil && exists {
					sub.mu.Lock()
					sub.LastNotify = time.Now()
					sub.mu.Unlock()
					if sub.Mode == ModeOnDemand {
						if delErr := a.subscriptionStore.DeleteSubscription(sub.ID); delErr != nil {
							a.logger.WithError(delErr).Debug("ees one-time subscription already removed")
						}
						delete(a.reportBuffer, sub.ID)
					}
				}
			}
			delete(a.inFlight, sub.ID)
			a.mu.Unlock()
			done <- err == nil
			a.signal()
		}(sub, batch)
	}
	return results, delay
}

// notificationPeriod rounds the requested period up to a whole number of URR
// measurement periods, so each notification carries complete kernel reports.
// Without a periodic URR (base 0) the requested period is used as is.
func notificationPeriod(requested, base time.Duration) time.Duration {
	if base <= 0 {
		return requested
	}
	return (requested + base - 1) / base * base
}

// periodicDue returns when a PERIODIC batch should be sent. With a periodic
// URR the batch is sent as soon as it spans the rounded period, aligned to
// report arrival so jitter cannot split measurement periods unevenly. If
// reports stop arriving (e.g. session release), the partial batch is sent half
// a measurement period after the deadline.
func periodicDue(last time.Time, requested time.Duration,
	batch map[SessionKey]*UsageMeasures, now time.Time,
) time.Time {
	var base, span time.Duration
	for _, m := range batch {
		base = max(base, m.MeasurePeriod)
		span = max(span, m.EndTime.Sub(m.StartTime))
	}
	period := notificationPeriod(requested, base)
	if base == 0 {
		return last.Add(period)
	}
	if span >= period-base/2 {
		return now
	}
	return last.Add(period + base/2)
}

func mergeMeasure(m map[SessionKey]*UsageMeasures, incoming *UsageMeasures) {
	existing, ok := m[incoming.Key]
	if !ok {
		m[incoming.Key] = incoming
		return
	}
	if incoming.StartTime.Before(existing.StartTime) {
		existing.StartTime = incoming.StartTime
	}
	if incoming.EndTime.After(existing.EndTime) {
		existing.EndTime = incoming.EndTime
	}
	existing.MeasurePeriod = max(existing.MeasurePeriod, incoming.MeasurePeriod)
	existing.ULBytesDelta += incoming.ULBytesDelta
	existing.DLBytesDelta += incoming.DLBytesDelta
	existing.ULPacketsDelta += incoming.ULPacketsDelta
	existing.DLPacketsDelta += incoming.DLPacketsDelta
}

// PushReportWithContext also accepts final reports after session removal.
// Identity must be captured before cleanup, never re-looked-up by a reused ID.
func (a *Aggregator) PushReportWithContext(sr report.SessReport, identity SessionContext) {
	if identity.UeIPv4Addr == "" {
		return
	}
	m := &UsageMeasures{
		Key: SessionKey{
			LocalSEID: sr.SEID, RemoteSEID: identity.RemoteSEID,
			Generation: identity.Generation, UEIPv4: identity.UeIPv4Addr,
		},
		UeIpv4Addr:    identity.UeIPv4Addr,
		MeasurePeriod: identity.MeasurePeriod,
	}
	count := 0
	for _, r := range sr.Reports {
		usage, ok := r.(report.USAReport)
		if !ok || usage.URRID != SingleUPFMAQEURRID {
			continue
		}
		// A real zero-volume measurement is valid; absent/invalid intervals are not.
		if usage.StartTime.IsZero() || !usage.EndTime.After(usage.StartTime) {
			continue
		}
		m.ULBytesDelta += usage.VolumMeasure.UplinkVolume
		m.DLBytesDelta += usage.VolumMeasure.DownlinkVolume
		m.ULPacketsDelta += usage.VolumMeasure.UplinkPktNum
		m.DLPacketsDelta += usage.VolumMeasure.DownlinkPktNum
		if count == 0 || usage.StartTime.Before(m.StartTime) {
			m.StartTime = usage.StartTime
		}
		if count == 0 || usage.EndTime.After(m.EndTime) {
			m.EndTime = usage.EndTime
		}
		count++
	}
	if count == 0 {
		return
	}
	a.mu.Lock()
	for _, sub := range a.subscriptionStore.AllSubscriptions() {
		if !a.matchesSubscription(sub, identity.UeIPv4Addr) {
			continue
		}
		if a.reportBuffer[sub.ID] == nil {
			a.reportBuffer[sub.ID] = make(map[SessionKey]*UsageMeasures)
		}
		measure := *m
		mergeMeasure(a.reportBuffer[sub.ID], &measure)
	}
	a.mu.Unlock()
	a.signal()
}

func (a *Aggregator) matchesSubscription(sub *Subscription, ip string) bool {
	return sub.Event == EventUserDataUsageMeasures && sub.Granularity == GranularityPerSession &&
		(sub.Target.AnyUE || (sub.Target.UeIPAddress != "" && sub.Target.UeIPAddress == ip))
}

func computeThroughputIfPossible(m *UsageMeasures) {
	seconds := m.EndTime.Sub(m.StartTime).Seconds()
	if seconds <= 0 {
		return
	}
	m.ULThroughputBps = float64(m.ULBytesDelta) * 8 / seconds
	m.DLThroughputBps = float64(m.DLBytesDelta) * 8 / seconds
	m.ULPacketThroughputPps = float64(m.ULPacketsDelta) / seconds
	m.DLPacketThroughputPps = float64(m.DLPacketsDelta) / seconds
}
