package imap

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/axllent/mailpit/internal/logger"
	"github.com/axllent/mailpit/internal/storage"
)

// literalRe matches the trailing "{N}" or "{N+}" literal token of an IMAP
// command line. The non-synchronizing form (with `+`) is RFC 7888
// LITERAL+ — the client streams bytes immediately without waiting for the
// server's continuation prompt.
var literalRe = regexp.MustCompile(`\{(\d+)(\+?)\}\s*$`)

// cmdAPPEND implements RFC 9051 §6.3.12 APPEND.
//
//	APPEND mailbox [(flag-list)] [date-time] literal
//
// We only accept INBOX as a destination (other names get TRYCREATE).
// Optional flag-list: we honour \Seen; everything else is ignored.
// Optional date-time: parsed but not used (storage.Store stamps Created
// at insertion time and there's no separate INTERNALDATE field).
func (s *session) cmdAPPEND(tag, rest string) {
	if s.state == stateUnauth {
		s.taggedNO(tag, "not authenticated")
		return
	}

	mailbox, flags, _, sizeStr, sync, err := parseAppendHeader(rest)
	if err != nil {
		s.taggedBAD(tag, "APPEND: "+err.Error())
		return
	}
	if !strings.EqualFold(mailbox, "INBOX") {
		s.taggedNO(tag, "[TRYCREATE] no such mailbox")
		return
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size < 0 {
		s.taggedBAD(tag, "APPEND: bad literal size")
		return
	}
	// Refuse absurd APPENDs to avoid OOM. 64MB matches mailpit's normal
	// SMTP message ceiling well enough for a dev tool.
	const maxAppend = 64 * 1024 * 1024
	if size > maxAppend {
		s.taggedNO(tag, "APPEND: message too large")
		return
	}

	if sync {
		// Non-synchronizing literal (RFC 7888): the client has already
		// started streaming. Read straight away.
	} else {
		// Synchronizing literal: tell the client to send the bytes.
		s.write("+ Ready for literal data")
	}

	body, err := readLiteral(s.reader, size)
	if err != nil {
		logger.Log().Warnf("[imap] APPEND read literal: %s", err.Error())
		// connection is desynchronised — bail
		s.idleErr = err
		return
	}

	// Drain the trailing CRLF the client sends after the literal.
	_, _ = s.reader.ReadString('\n')

	id, err := storage.Store(&body, &s.user)
	if err != nil {
		logger.Log().Errorf("[imap] APPEND store: %s", err.Error())
		s.taggedNO(tag, "APPEND: storage error")
		return
	}

	uid := uidFor(id)

	// Honour \Seen if requested; ignore other flags. \Deleted on a
	// just-appended message is silly so we let it ride for honesty.
	for _, f := range flags {
		if strings.EqualFold(f, `\Seen`) {
			_ = storage.MarkRead([]string{id})
			s.flagsSeen[id] = true
		}
	}

	// APPENDUID response code (RFC 4315) so capable clients can fast-path
	// to the new message without re-listing.
	s.taggedOK(tag, fmt.Sprintf("[APPENDUID %d %d] APPEND completed",
		uidValidityValue(), uid))
}

// parseAppendHeader extracts the components from the APPEND command line
// before the literal payload. Examples:
//
//	INBOX {1234}
//	INBOX (\Seen) {1234+}
//	"INBOX" (\Seen \Flagged) "17-Jul-2026 15:00:00 -0700" {1234}
//
// The returned `sync` is true when the client used `{N+}` (LITERAL+) and
// is therefore not waiting for a server continuation.
func parseAppendHeader(line string) (mailbox string, flags []string, dateTime, size string, sync bool, err error) {
	m := literalRe.FindStringSubmatch(line)
	if m == nil {
		err = errors.New("expected literal {N} or {N+}")
		return
	}
	size = m[1]
	sync = m[2] == "+"
	head := strings.TrimRight(line[:len(line)-len(m[0])], " \t")

	tokens := tokenize(head)
	if len(tokens) == 0 {
		err = errors.New("missing mailbox")
		return
	}
	mailbox = tokens[0]
	tokens = tokens[1:]

	// optional flag list (parenthesized)
	if len(tokens) > 0 && strings.HasPrefix(tokens[0], "(") && strings.HasSuffix(tokens[0], ")") {
		flagBody := parenContents(tokens[0])
		for _, f := range strings.Fields(flagBody) {
			flags = append(flags, f)
		}
		tokens = tokens[1:]
	}

	// optional date-time
	if len(tokens) > 0 {
		dateTime = tokens[0]
	}
	return
}

// readLiteral reads exactly n bytes from r. Used for APPEND payloads.
func readLiteral(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
