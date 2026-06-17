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
}

// NewSubscriptionStore creates a new, empty store for subscriptions.
func NewSubscriptionStore(instanceSuffix string) *SubscriptionStore {
	return &SubscriptionStore{
		subscriptionsByID: make(map[string]*Subscription),
		instanceSuffixStr: instanceSuffix,
	}
}

// CreateSubscription inserts a subscription and returns its generated ID.
// Minimal validation is performed to reduce accidental bad states.
func (store *SubscriptionStore) CreateSubscription(newSubscription *Subscription) (string, error) {
	if newSubscription == nil {
		return "", ErrInvalidSubscription
	}
	if newSubscription.NotifURI == "" {
		return "", fmt.Errorf("%w: missing NotifURI", ErrInvalidSubscription)
	}
	if newSubscription.Event == "" {
		return "", fmt.Errorf("%w: missing Event", ErrInvalidSubscription)
	}
	if newSubscription.Granularity == "" {
		return "", fmt.Errorf("%w: missing Granularity", ErrInvalidSubscription)
	}
	if newSubscription.Mode == "" {
		return "", fmt.Errorf("%w: missing Mode", ErrInvalidSubscription)
	}
	// PeriodSec is only required for PERIODIC mode
	if newSubscription.Mode == ModePeriodic && newSubscription.PeriodSec <= 0 {
		return "", fmt.Errorf("%w: PeriodSec must be > 0 for PERIODIC mode", ErrInvalidSubscription)
	}
	if newSubscription.NfID == "" {
		return "", fmt.Errorf("%w: missing NfID", ErrInvalidSubscription)
	}
	if newSubscription.NotifyCorrelationID == "" {
		return "", fmt.Errorf("%w: missing NotifyCorrelationID", ErrInvalidSubscription)
	}

	subscriptionID := store.generateSubscriptionID()
	now := time.Now()

	// initialize internal bookkeeping fields
	newSubscription.ID = subscriptionID
	newSubscription.CreatedAt = now
	newSubscription.LastNotify = now // Initialize to now to avoid time overflow
	if newSubscription.Snapshots == nil {
		newSubscription.Snapshots = make(map[SessionKey]Counters)
	}

	store.mutexForSubscriptions.Lock()
	store.subscriptionsByID[subscriptionID] = newSubscription
	store.mutexForSubscriptions.Unlock()

	return subscriptionID, nil
}

// DeleteSubscription removes a subscription by ID.
func (store *SubscriptionStore) DeleteSubscription(subscriptionID string) error {
	store.mutexForSubscriptions.Lock()
	defer store.mutexForSubscriptions.Unlock()

	if _, ok := store.subscriptionsByID[subscriptionID]; !ok {
		return ErrSubscriptionNotFound
	}
	delete(store.subscriptionsByID, subscriptionID)
	return nil
}

// GetSubscription returns the subscription pointer for the given ID and a boolean indicating presence.
// Callers should treat the returned pointer as read-mostly; mutations should be protected externally
// if done concurrently with other operations.
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
