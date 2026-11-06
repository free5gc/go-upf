// Package ees - UPF Event Exposure Service (EES)
// subscription_store.go: thread-safe in-memory store for EES subscriptions.
//
// Scope:
// - Only manages subscriptions (create/delete/get/list).
// - ID generation is local, simple, and collision-resistant enough for MVP.
package ees

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// ErrSubscriptionNotFound is returned when a subscription ID does not exist.
var ErrSubscriptionNotFound = errors.New("subscription not found")

// ErrInvalidSubscription is returned when a subscription is nil or missing required fields.
var ErrInvalidSubscription = errors.New("invalid subscription")

// SubscriptionStore is a thread-safe in-memory storage for EES subscriptions.
// It intentionally uses descriptive field names for readability and maintenance.
type SubscriptionStore struct {
	mutexForSubscriptions sync.RWMutex
	subscriptionsByID     map[string]*Subscription

	// simple in-process ID generator state
	mutexForIDGen     sync.Mutex
	lastTimestampNS   int64
	sequencePerTS     uint32
	instanceSuffixStr string // optional, e.g., hostname or short random; empty is fine for MVP
	changed           chan struct{}
	// watchers are extra change listeners (e.g. the PFCP loop that reconciles
	// UPF-owned URRs). Registered before the store is used concurrently.
	watchers []chan struct{}
}

// NewSubscriptionStore creates a new, empty store for subscriptions.
func NewSubscriptionStore(instanceSuffix string) *SubscriptionStore {
	return &SubscriptionStore{
		subscriptionsByID: make(map[string]*Subscription),
		changed:           make(chan struct{}, 1),
		instanceSuffixStr: instanceSuffix,
	}
}

// CreateSubscription inserts a subscription and returns its generated ID.
// Minimal validation is performed to reduce accidental bad states.
func (store *SubscriptionStore) CreateSubscription(newSubscription *Subscription) (string, error) {
	if err := validateSubscription(newSubscription); err != nil {
		return "", err
	}

	subscriptionID := store.generateSubscriptionID()
	now := time.Now()

	// initialize internal bookkeeping fields
	newSubscription.ID = subscriptionID
	newSubscription.CreatedAt = now
	newSubscription.LastNotify = now // Initialize to now to avoid time overflow

	store.mutexForSubscriptions.Lock()
	store.subscriptionsByID[subscriptionID] = newSubscription
	store.mutexForSubscriptions.Unlock()
	store.signalChange()

	return subscriptionID, nil
}

// validateSubscription performs the minimal checks shared by create and replace.
func validateSubscription(subscription *Subscription) error {
	if subscription == nil {
		return ErrInvalidSubscription
	}
	if subscription.NotifURI == "" {
		return fmt.Errorf("%w: missing NotifURI", ErrInvalidSubscription)
	}
	if subscription.Event == "" {
		return fmt.Errorf("%w: missing Event", ErrInvalidSubscription)
	}
	if subscription.Granularity == "" {
		return fmt.Errorf("%w: missing Granularity", ErrInvalidSubscription)
	}
	if subscription.Mode == "" {
		return fmt.Errorf("%w: missing Mode", ErrInvalidSubscription)
	}
	// PeriodSec is only required for PERIODIC mode
	if subscription.Mode == ModePeriodic &&
		(subscription.PeriodSec <= 0 || subscription.PeriodSec > math.MaxInt32) {
		return fmt.Errorf("%w: PeriodSec must be a positive DurationSec for PERIODIC mode", ErrInvalidSubscription)
	}
	if subscription.NfID == "" {
		return fmt.Errorf("%w: missing NfID", ErrInvalidSubscription)
	}
	if subscription.NotifyCorrelationID == "" {
		return fmt.Errorf("%w: missing NotifyCorrelationID", ErrInvalidSubscription)
	}
	return nil
}

// ReplaceSubscription stores updated under the ID of current, keeping its ID,
// CreatedAt and LastNotify. Subscriptions are replaced, never edited in place,
// so readers holding the old pointer see a consistent value. It returns
// ErrSubscriptionNotFound if current is no longer the stored subscription.
func (store *SubscriptionStore) ReplaceSubscription(current, updated *Subscription) error {
	if current == nil {
		return ErrSubscriptionNotFound
	}
	if err := validateSubscription(updated); err != nil {
		return err
	}

	store.mutexForSubscriptions.Lock()
	defer store.mutexForSubscriptions.Unlock()

	if store.subscriptionsByID[current.ID] != current {
		return ErrSubscriptionNotFound
	}
	current.mu.RLock()
	updated.ID, updated.CreatedAt, updated.LastNotify = current.ID, current.CreatedAt, current.LastNotify
	current.mu.RUnlock()
	store.subscriptionsByID[current.ID] = updated
	store.signalChange()
	return nil
}

// DeleteSubscription removes a subscription by ID.
func (store *SubscriptionStore) DeleteSubscription(subscriptionID string) error {
	store.mutexForSubscriptions.Lock()
	defer store.mutexForSubscriptions.Unlock()

	if _, ok := store.subscriptionsByID[subscriptionID]; !ok {
		return ErrSubscriptionNotFound
	}
	delete(store.subscriptionsByID, subscriptionID)
	store.signalChange()
	return nil
}

func (store *SubscriptionStore) signalChange() {
	select {
	case store.changed <- struct{}{}:
	default:
	}
	for _, watcher := range store.watchers {
		select {
		case watcher <- struct{}{}:
		default:
		}
	}
}

// Watch returns a coalescing channel that receives a value after any
// subscription is created or deleted. Call it before the store is shared.
func (store *SubscriptionStore) Watch() <-chan struct{} {
	watcher := make(chan struct{}, 1)
	store.watchers = append(store.watchers, watcher)
	return watcher
}

// GetSubscription returns the subscription pointer for the given ID and a boolean indicating presence.
// Callers should treat the returned pointer as read-mostly; mutations should be protected externally
// if done concurrently with other operations. A PATCH replaces the pointer stored under the ID.
func (store *SubscriptionStore) GetSubscription(subscriptionID string) (*Subscription, bool) {
	store.mutexForSubscriptions.RLock()
	subscription, ok := store.subscriptionsByID[subscriptionID]
	store.mutexForSubscriptions.RUnlock()
	return subscription, ok
}

// AllSubscriptions returns a snapshot slice of all current subscriptions.
// The returned slice is safe to iterate without holding the store lock.
func (store *SubscriptionStore) AllSubscriptions() []*Subscription {
	store.mutexForSubscriptions.RLock()
	defer store.mutexForSubscriptions.RUnlock()

	list := make([]*Subscription, 0, len(store.subscriptionsByID))
	for _, subscription := range store.subscriptionsByID {
		list = append(list, subscription)
	}
	return list
}

// generateSubscriptionID creates a sortable, mostly-unique ID composed of:
//   - unix time in nanoseconds
//   - a per-timestamp sequence (for same-ns collisions)
//   - an optional instance suffix (configurable at store creation)
//
// Format example: "sub-1730023456789012345-0001-hostA"
func (store *SubscriptionStore) generateSubscriptionID() string {
	nowNS := time.Now().UnixNano()

	store.mutexForIDGen.Lock()
	if nowNS != store.lastTimestampNS {
		store.lastTimestampNS = nowNS
		store.sequencePerTS = 0
	} else {
		store.sequencePerTS++
	}
	sequenceCopy := store.sequencePerTS
	instanceSuffixCopy := store.instanceSuffixStr
	store.mutexForIDGen.Unlock()

	if instanceSuffixCopy != "" {
		return fmt.Sprintf("sub-%d-%04d-%s", nowNS, sequenceCopy, instanceSuffixCopy)
	}
	return fmt.Sprintf("sub-%d-%04d", nowNS, sequenceCopy)
}
