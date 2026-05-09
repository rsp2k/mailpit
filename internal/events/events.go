// Package events provides a tiny in-process pub/sub bus.
//
// Storage publishes lifecycle events (new, delete, prune, truncate) to this
// bus. Subscribers (currently the IMAP server's IDLE sessions) receive them
// on a buffered channel. Publish is non-blocking: if a subscriber's channel
// is full, the event is dropped for that subscriber rather than blocking
// the publisher. Subscribers that fall behind should expect to miss events
// and resync from storage when convenient.
package events

import "sync"

// Event is a single pub/sub message.
type Event struct {
	Type string
	Data any
}

// Subscriber is a buffered receive channel returned from Subscribe.
type Subscriber chan Event

const subscriberBuffer = 32

var (
	mu   sync.RWMutex
	subs = map[Subscriber]struct{}{}
)

// Subscribe registers a new subscriber and returns its channel.
func Subscribe() Subscriber {
	ch := make(Subscriber, subscriberBuffer)
	mu.Lock()
	subs[ch] = struct{}{}
	mu.Unlock()
	return ch
}

// Unsubscribe removes the subscriber and closes its channel. Safe to call
// once; subsequent calls with the same channel are no-ops.
func Unsubscribe(ch Subscriber) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := subs[ch]; !ok {
		return
	}
	delete(subs, ch)
	close(ch)
}

// Publish fans out the event to all current subscribers without blocking.
func Publish(eventType string, data any) {
	mu.RLock()
	defer mu.RUnlock()
	if len(subs) == 0 {
		return
	}
	e := Event{Type: eventType, Data: data}
	for ch := range subs {
		select {
		case ch <- e:
		default:
		}
	}
}
