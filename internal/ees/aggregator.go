package ees

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/report"
)

// SingleUPFMAQEURRID is the free5GC single-UPF, after-QoS measurement rule.
// It is session-scoped, not a global counter. ULCL and arbitrary SMF URR
// allocations are outside this MVP; do not sum all URRs (they may overlap).
const SingleUPFMAQEURRID uint32 = 2

// oneTimeSourceWait bounds how long a ONE_TIME subscription that reads both
// URRs stays open for the second source after the first one has delivered.
// The SMF may not provision URR 2 at all.
const oneTimeSourceWait = 10 * time.Second

// stream is one URR source of one subscription. Streams are buffered and
// scheduled independently, so a subscription that reads both URRs gets
// separate notifications and one source cannot delay or change the other.
type stream struct {
	subscriptionID string
	source         MeasurementSource
}

// Aggregator buffers real measurements and schedules each stream
// independently. It never manufactures measurements for an empty buffer.
type Aggregator struct {
	subscriptionStore *SubscriptionStore
	notifier          *Notifier
	logger            *logrus.Entry
	// mu guards the per-stream scheduling state below.
	mu              sync.Mutex
	reportBuffer    map[stream]map[SessionKey]*UsageMeasures // pending usage per stream
	inFlight        map[stream]bool                          // a notification is being sent
	retryAt         map[stream]time.Time                     // earliest retry after a failed send
	lastSent        map[stream]time.Time                     // last successful notification
	oneTimeSent     map[stream]bool                          // ONE_TIME stream already delivered
	oneTimeDeadline map[string]time.Time                     // by subscription ID: stop waiting for a source
	oneTimeWait     time.Duration
	wake            chan struct{}
	workers         sync.WaitGroup
}

func NewAggregator(store *SubscriptionStore, notifier *Notifier, logger *logrus.Entry) *Aggregator {
	return &Aggregator{
		subscriptionStore: store, notifier: notifier, logger: logger,
		reportBuffer: make(map[stream]map[SessionKey]*UsageMeasures),
		inFlight:     make(map[stream]bool), retryAt: make(map[stream]time.Time),
		lastSent: make(map[stream]time.Time), oneTimeSent: make(map[stream]bool),
		oneTimeDeadline: make(map[string]time.Time), oneTimeWait: oneTimeSourceWait,
		wake: make(chan struct{}, 1),
	}
}

func (a *Aggregator) signal() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// Run launches at most one notification per stream at a time. A slow
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
	a.forgetDeletedSubscriptions()
	for _, sub := range a.subscriptionStore.AllSubscriptions() {
		for _, source := range sub.Sources() {
			st := stream{sub.ID, source}
			batch := a.reportBuffer[st]
			if a.inFlight[st] || len(batch) == 0 {
				continue
			}
			sub.mu.RLock()
			last, sent := a.lastSent[st]
			if !sent {
				last = sub.LastNotify
			}
			due := periodicDue(last, time.Duration(sub.PeriodSec)*time.Second, batch, now)
			if sub.Mode == ModeOnDemand {
				due = now
			}
			sub.mu.RUnlock()
			if retry := a.retryAt[st]; retry.After(due) {
				due = retry
			}
			if due.After(now) {
				if remaining := due.Sub(now); remaining < delay {
					delay = remaining
				}
				continue
			}
			delete(a.reportBuffer, st)
			a.inFlight[st] = true
			done := make(chan bool, 1)
			results = append(results, done)
			a.workers.Add(1)
			go a.send(ctx, sub, st, batch, done)
		}
		if remaining := a.finishOneTime(sub, now); remaining > 0 && remaining < delay {
			delay = remaining
		}
	}
	return results, delay
}

// send delivers one batch of a stream and records the outcome.
func (a *Aggregator) send(ctx context.Context, sub *Subscription, st stream,
	batch map[SessionKey]*UsageMeasures, done chan<- bool,
) {
	defer a.workers.Done()
	measures := make([]UsageMeasures, 0, len(batch))
	for _, m := range batch {
		computeThroughputIfPossible(m)
		measures = append(measures, *m)
	}
	err := a.notifier.NotifyContext(ctx, sub, measures)
	a.mu.Lock()
	delete(a.inFlight, st)
	_, exists := a.subscriptionStore.GetSubscription(sub.ID)
	if err != nil && exists {
		if a.reportBuffer[st] == nil {
			a.reportBuffer[st] = make(map[SessionKey]*UsageMeasures)
		}
		for _, m := range batch {
			mergeMeasure(a.reportBuffer[st], m)
		}
		a.retryAt[st] = time.Now().Add(time.Second)
		a.logger.WithError(err).Warn("ees notification failed; retaining measurements")
	} else {
		delete(a.retryAt, st)
		if err == nil && exists {
			sentAt := time.Now()
			a.lastSent[st] = sentAt
			sub.mu.Lock()
			sub.LastNotify = sentAt
			sub.mu.Unlock()
			if sub.Mode == ModeOnDemand {
				a.oneTimeSent[st] = true
				delete(a.reportBuffer, st)
				a.finishOneTime(sub, sentAt)
			}
		}
	}
	a.mu.Unlock()
	done <- err == nil
	a.signal()
}

// finishOneTime deletes a ONE_TIME subscription once every source has delivered
// its first real measurement. A source that stays silent is given oneTimeWait
// after the first delivery. It returns how long the subscription still waits.
func (a *Aggregator) finishOneTime(sub *Subscription, now time.Time) time.Duration {
	if sub.Mode != ModeOnDemand {
		return 0
	}
	sources := sub.Sources()
	delivered := 0
	for _, source := range sources {
		st := stream{sub.ID, source}
		if a.oneTimeSent[st] {
			delivered++
		} else if a.inFlight[st] || len(a.reportBuffer[st]) > 0 {
			return 0
		}
	}
	if delivered == 0 {
		return 0
	}
	if delivered < len(sources) {
		deadline, waiting := a.oneTimeDeadline[sub.ID]
		if !waiting {
			deadline = now.Add(a.oneTimeWait)
			a.oneTimeDeadline[sub.ID] = deadline
		}
		if now.Before(deadline) {
			return deadline.Sub(now)
		}
	}
	if err := a.subscriptionStore.DeleteSubscription(sub.ID); err != nil {
		a.logger.WithError(err).Debug("ees one-time subscription already removed")
	}
	a.forgetDeletedSubscriptions()
	return 0
}

// forgetDeletedSubscriptions drops the scheduling state of deleted subscriptions.
func (a *Aggregator) forgetDeletedSubscriptions() {
	deleted := func(id string) bool {
		_, exists := a.subscriptionStore.GetSubscription(id)
		return !exists
	}
	maps.DeleteFunc(a.reportBuffer, func(st stream, _ map[SessionKey]*UsageMeasures) bool {
		return deleted(st.subscriptionID)
	})
	maps.DeleteFunc(a.retryAt, func(st stream, _ time.Time) bool { return deleted(st.subscriptionID) })
	maps.DeleteFunc(a.lastSent, func(st stream, _ time.Time) bool { return deleted(st.subscriptionID) })
	maps.DeleteFunc(a.oneTimeSent, func(st stream, _ bool) bool { return deleted(st.subscriptionID) })
	maps.DeleteFunc(a.oneTimeDeadline, func(id string, _ time.Time) bool { return deleted(id) })
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
	// Each stream reads exactly one URR: URR 2 (SMF source) or the UPF-owned
	// URR (UPF source). The two are never summed.
	smfUsage := usageFromReports(sr, identity, SingleUPFMAQEURRID, identity.MeasurePeriod)
	var upfUsage *UsageMeasures
	if identity.UPFURRID != 0 {
		upfUsage = usageFromReports(sr, identity, identity.UPFURRID, identity.UPFURRPeriod)
	}
	if smfUsage == nil && upfUsage == nil {
		return
	}
	a.mu.Lock()
	for _, sub := range a.subscriptionStore.AllSubscriptions() {
		if !MatchesTarget(sub, identity) {
			continue
		}
		for _, source := range sub.Sources() {
			m := smfUsage
			if source == SourceUPFURR {
				m = upfUsage
			}
			st := stream{sub.ID, source}
			if m == nil || (sub.Mode == ModeOnDemand && a.oneTimeSent[st]) {
				continue
			}
			if a.reportBuffer[st] == nil {
				a.reportBuffer[st] = make(map[SessionKey]*UsageMeasures)
			}
			measure := *m
			measure.Source = source
			mergeMeasure(a.reportBuffer[st], &measure)
		}
	}
	a.mu.Unlock()
	a.signal()
}

// usageFromReports sums the valid usage reports of one URR, or returns nil.
func usageFromReports(sr report.SessReport, identity SessionContext, urrID uint32,
	period time.Duration,
) *UsageMeasures {
	m := &UsageMeasures{
		Key: SessionKey{
			LocalSEID: sr.SEID, RemoteSEID: identity.RemoteSEID,
			Generation: identity.Generation, UEIPv4: identity.UeIPv4Addr,
		},
		UeIpv4Addr:    identity.UeIPv4Addr,
		MeasurePeriod: period,
	}
	count := 0
	for _, r := range sr.Reports {
		usage, ok := r.(report.USAReport)
		if !ok || usage.URRID != urrID {
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
		return nil
	}
	return m
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
