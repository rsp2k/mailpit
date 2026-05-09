package imap

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/axllent/mailpit/internal/logger"
	"github.com/axllent/mailpit/internal/storage"
)

// session state machine.
const (
	stateUnauth   = 1
	stateAuth     = 2
	stateSelected = 3
	stateLogout   = 4
)

// sessionMessage is one message visible to a SELECT-ed session.
// IMAP semantics: a session sees a fixed snapshot of the mailbox until it
// is updated by NOOP, IDLE, or another SELECT.
type sessionMessage struct {
	uid     uint32
	id      string // storage ID
	deleted bool   // \Deleted flag pending EXPUNGE
}

// session holds the per-connection IMAP state.
type session struct {
	conn   net.Conn
	reader *bufio.Reader
	user   string

	state     int
	mailbox   string // "INBOX" when selected, "" otherwise
	readOnly  bool   // true after EXAMINE
	messages  []sessionMessage
	flagsSeen map[string]bool // per-session \Seen view; truth is in storage.Read

	idleErr error
}

// newSession constructs a session attached to conn.
func newSession(conn net.Conn) *session {
	return &session{
		conn:      conn,
		reader:    bufio.NewReader(conn),
		state:     stateUnauth,
		flagsSeen: map[string]bool{},
	}
}

// write sends a single CRLF-terminated line and debug-logs it.
func (s *session) write(line string) {
	_, _ = fmt.Fprint(s.conn, line, "\r\n")
	logger.Log().Debugf("[imap] -> %s", line)
}

// writef is like write with Printf-style formatting.
func (s *session) writef(format string, args ...any) {
	s.write(fmt.Sprintf(format, args...))
}

// writeRaw sends bytes without appending CRLF (used for literal payloads).
func (s *session) writeRaw(b []byte) {
	_, _ = s.conn.Write(b)
}

// taggedOK / taggedBAD / taggedNO are convenience response helpers.
func (s *session) taggedOK(tag, msg string)  { s.writef("%s OK %s", tag, msg) }
func (s *session) taggedBAD(tag, msg string) { s.writef("%s BAD %s", tag, msg) }
func (s *session) taggedNO(tag, msg string)  { s.writef("%s NO %s", tag, msg) }

// snapshot rebuilds session.messages from storage. Returns the new slice
// and the list of UIDs that disappeared since the last snapshot (for
// EXPUNGE notifications). Sequence #1 is the oldest message in the
// mailbox per IMAP convention; storage.List orders newest-first so we
// reverse.
func (s *session) snapshot() ([]sessionMessage, []uint32) {
	rows, err := storage.List(0, 0, 0)
	if err != nil {
		logger.Log().Errorf("[imap] list error: %s", err.Error())
		return s.messages, nil
	}

	// build ordered list, oldest first
	ordered := make([]sessionMessage, 0, len(rows))
	// storage.List is newest-first; iterate in reverse for oldest-first
	for i := len(rows) - 1; i >= 0; i-- {
		m := rows[i]
		ordered = append(ordered, sessionMessage{
			uid: uidFor(m.ID),
			id:  m.ID,
		})
		s.flagsSeen[m.ID] = m.Read
	}

	// determine which previously-known UIDs are gone
	current := map[uint32]struct{}{}
	for _, m := range ordered {
		current[m.uid] = struct{}{}
	}
	var gone []uint32
	for _, prev := range s.messages {
		if _, ok := current[prev.uid]; !ok {
			gone = append(gone, prev.uid)
		}
	}
	// EXPUNGE responses must be in descending sequence order; UIDs roughly
	// correlate but we re-resolve by old sequence number anyway.
	sort.Slice(gone, func(i, j int) bool { return gone[i] > gone[j] })

	return ordered, gone
}

// applySnapshot replaces session.messages with the new slice.
func (s *session) applySnapshot(next []sessionMessage) {
	s.messages = next
}

// uidToSeq returns the 1-based sequence number for a UID in this session,
// or 0/false if not present.
func (s *session) uidToSeq(u uint32) (int, bool) {
	for i, m := range s.messages {
		if m.uid == u {
			return i + 1, true
		}
	}
	return 0, false
}

// flagsList returns the IMAP flags string for a message (e.g. "\Seen").
func (s *session) flagsList(id string) string {
	parts := []string{}
	if s.flagsSeen[id] {
		parts = append(parts, `\Seen`)
	}
	return strings.Join(parts, " ")
}

// readDeadline updates the connection read deadline.
func (s *session) readDeadline(d time.Duration) {
	if err := s.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		logger.Log().Debugf("[imap] set deadline: %s", err.Error())
	}
}
