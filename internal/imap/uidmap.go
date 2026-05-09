package imap

import (
	"sync"
	"sync/atomic"
	"time"
)

// UIDVALIDITY is set once at process start. IMAP clients treat a change in
// UIDVALIDITY as a signal to discard cached UIDs and resync the mailbox,
// which is what we want after every mailpit restart since UID assignments
// are purely in-memory.
var uidValidity = uint32(time.Now().Unix())

// nextUID is the source of new UIDs. Starts at 1 (UIDs must be > 0 per
// RFC 9051) and increments atomically per never-before-seen message ID.
var nextUID atomic.Uint32

// uidMap is the global, process-wide mapping between Mailpit's string
// message IDs and IMAP's uint32 UIDs. Both directions are kept so that
// FETCH-by-UID and lookup-while-listing are O(1). Once assigned a UID is
// permanent for the life of the process — that is the whole point of
// IMAP UIDs.
var uidMap = struct {
	sync.RWMutex
	byID  map[string]uint32
	byUID map[uint32]string
}{
	byID:  make(map[string]uint32),
	byUID: make(map[uint32]string),
}

// uidFor returns the UID for a message ID, allocating a new one on first
// sight. Safe for concurrent use.
func uidFor(id string) uint32 {
	uidMap.RLock()
	if u, ok := uidMap.byID[id]; ok {
		uidMap.RUnlock()
		return u
	}
	uidMap.RUnlock()

	uidMap.Lock()
	defer uidMap.Unlock()
	// re-check under write lock in case another goroutine assigned one
	if u, ok := uidMap.byID[id]; ok {
		return u
	}
	u := nextUID.Add(1)
	uidMap.byID[id] = u
	uidMap.byUID[u] = id
	return u
}

// idForUID returns the message ID for a UID, or "" if unknown.
func idForUID(u uint32) string {
	uidMap.RLock()
	defer uidMap.RUnlock()
	return uidMap.byUID[u]
}

// uidNext is the UID a future message would receive. Reported in
// SELECT / STATUS responses.
func uidNext() uint32 {
	return nextUID.Load() + 1
}

func uidValidityValue() uint32 {
	return uidValidity
}
