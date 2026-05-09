package imap

import (
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/axllent/mailpit/internal/auth"
	"github.com/axllent/mailpit/internal/events"
	"github.com/axllent/mailpit/internal/logger"
	"github.com/axllent/mailpit/internal/storage"
)

// authenticate checks IMAP credentials. We share POP3's credential set
// (see config validation) so the same htpasswd file works for both.
func authenticate(user, pass string) bool {
	if auth.POP3Credentials == nil {
		return false
	}
	return auth.POP3Credentials.Match(user, pass)
}

// dispatch handles a single client command line.
func (s *session) dispatch(line string) bool {
	tag, cmd, rest, err := parseLine(line)
	if err != nil {
		s.write("* BAD parse error")
		return true
	}

	logger.Log().Debugf("[imap] <- %s %s %s", tag, cmd, rest)

	switch cmd {
	case "CAPABILITY":
		s.cmdCAPABILITY(tag)
	case "NOOP":
		s.cmdNOOP(tag)
	case "LOGOUT":
		s.cmdLOGOUT(tag)
		return false
	case "LOGIN":
		s.cmdLOGIN(tag, rest)
	case "AUTHENTICATE":
		s.cmdAUTHENTICATE(tag, rest)
	case "LIST":
		s.cmdLIST(tag, rest, false)
	case "LSUB":
		s.cmdLIST(tag, rest, true)
	case "SELECT":
		s.cmdSELECT(tag, rest, false)
	case "EXAMINE":
		s.cmdSELECT(tag, rest, true)
	case "STATUS":
		s.cmdSTATUS(tag, rest)
	case "FETCH":
		s.cmdFETCH(tag, rest, false)
	case "STORE":
		s.cmdSTORE(tag, rest, false)
	case "SEARCH":
		s.cmdSEARCH(tag, rest, false)
	case "UID":
		s.cmdUID(tag, rest)
	case "EXPUNGE":
		s.cmdEXPUNGE(tag)
	case "CLOSE":
		s.cmdCLOSE(tag)
	case "IDLE":
		s.cmdIDLE(tag)
	case "CHECK":
		s.taggedOK(tag, "CHECK completed")
	case "SUBSCRIBE", "UNSUBSCRIBE":
		// We pretend everything is subscribed.
		s.taggedOK(tag, cmd+" completed")
	case "ID":
		// RFC 2971 — clients send their identity, we respond with ours.
		s.write(`* ID ("name" "Mailpit" "version" "imap-basic")`)
		s.taggedOK(tag, "ID completed")
	case "APPEND":
		s.cmdAPPEND(tag, rest)
	case "COPY":
		s.cmdCOPY(tag, rest, false)
	case "MOVE":
		s.taggedNO(tag, "MOVE not supported (Mailpit has a single mailbox)")
	default:
		s.taggedBAD(tag, "unknown command")
	}
	return true
}

func (s *session) cmdCAPABILITY(tag string) {
	caps := []string{"IMAP4rev1", "AUTH=PLAIN", "IDLE", "UIDPLUS", "LITERAL+", "ID"}
	s.write("* CAPABILITY " + strings.Join(caps, " "))
	s.taggedOK(tag, "CAPABILITY completed")
}

func (s *session) cmdNOOP(tag string) {
	if s.state == stateSelected {
		next, gone := s.snapshot()
		// Emit EXPUNGE for vanished messages (descending sequence first)
		s.emitExpunges(gone)
		// Update the session view
		prevCount := len(s.messages)
		s.applySnapshot(next)
		if len(next) != prevCount-len(gone) {
			s.writef("* %d EXISTS", len(next))
		}
	}
	s.taggedOK(tag, "NOOP completed")
}

func (s *session) cmdLOGOUT(tag string) {
	s.write("* BYE Mailpit IMAP server logging out")
	s.taggedOK(tag, "LOGOUT completed")
	s.state = stateLogout
}

func (s *session) cmdLOGIN(tag, rest string) {
	if s.state != stateUnauth {
		s.taggedBAD(tag, "already authenticated")
		return
	}
	args := tokenize(rest)
	if len(args) < 2 {
		s.taggedBAD(tag, "LOGIN requires username and password")
		return
	}
	user, pass := args[0], args[1]
	if !authenticate(user, pass) {
		logger.Log().Warnf("[imap] failed login: %s", user)
		s.taggedNO(tag, "LOGIN failed")
		return
	}
	s.user = user
	s.state = stateAuth
	s.taggedOK(tag, "LOGIN completed")
}

// cmdAUTHENTICATE handles AUTHENTICATE PLAIN with the initial-response
// continuation. We don't bother with SASL state machines — the only
// mechanism advertised is PLAIN.
func (s *session) cmdAUTHENTICATE(tag, rest string) {
	args := tokenize(rest)
	if len(args) == 0 || !strings.EqualFold(args[0], "PLAIN") {
		s.taggedNO(tag, "unsupported mechanism")
		return
	}

	var b64 string
	if len(args) >= 2 {
		b64 = args[1]
	} else {
		s.write("+ ")
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		b64 = strings.TrimRight(line, "\r\n")
	}

	// PLAIN is base64( authzid \0 authcid \0 password )
	raw, err := base64Decode(b64)
	if err != nil {
		s.taggedNO(tag, "invalid base64")
		return
	}
	parts := strings.SplitN(raw, "\x00", 3)
	if len(parts) != 3 {
		s.taggedNO(tag, "invalid PLAIN response")
		return
	}
	user, pass := parts[1], parts[2]
	if !authenticate(user, pass) {
		s.taggedNO(tag, "AUTHENTICATE failed")
		return
	}
	s.user = user
	s.state = stateAuth
	s.taggedOK(tag, "AUTHENTICATE completed")
}

func (s *session) cmdLIST(tag, rest string, lsub bool) {
	if s.state == stateUnauth {
		s.taggedNO(tag, "not authenticated")
		return
	}
	// Just return INBOX — this server has no folder hierarchy.
	verb := "LIST"
	if lsub {
		verb = "LSUB"
	}
	s.writef(`* %s () "/" "INBOX"`, verb)
	s.taggedOK(tag, verb+" completed")
}

func (s *session) cmdSELECT(tag, rest string, readOnly bool) {
	if s.state == stateUnauth {
		s.taggedNO(tag, "not authenticated")
		return
	}
	args := tokenize(rest)
	if len(args) < 1 {
		s.taggedBAD(tag, "missing mailbox")
		return
	}
	if !strings.EqualFold(args[0], "INBOX") {
		s.taggedNO(tag, "no such mailbox")
		return
	}

	next, _ := s.snapshot()
	s.applySnapshot(next)
	s.mailbox = "INBOX"
	s.readOnly = readOnly
	s.state = stateSelected

	unseen := 0
	for _, m := range s.messages {
		if !s.flagsSeen[m.id] {
			unseen++
		}
	}

	s.writef("* %d EXISTS", len(s.messages))
	s.writef("* %d RECENT", 0)
	s.write(`* FLAGS (\Seen \Deleted)`)
	s.write(`* OK [PERMANENTFLAGS (\Seen \Deleted)] flags permitted`)
	s.writef("* OK [UIDVALIDITY %d] UIDs valid", uidValidityValue())
	s.writef("* OK [UIDNEXT %d] next UID", uidNext())
	if unseen > 0 {
		// First unseen message's sequence number
		for i, m := range s.messages {
			if !s.flagsSeen[m.id] {
				s.writef("* OK [UNSEEN %d] first unseen", i+1)
				break
			}
		}
	}

	resp := "[READ-WRITE] SELECT completed"
	if readOnly {
		resp = "[READ-ONLY] EXAMINE completed"
	}
	s.taggedOK(tag, resp)
}

func (s *session) cmdSTATUS(tag, rest string) {
	if s.state == stateUnauth {
		s.taggedNO(tag, "not authenticated")
		return
	}
	args := tokenize(rest)
	if len(args) < 2 {
		s.taggedBAD(tag, "STATUS needs mailbox and items")
		return
	}
	if !strings.EqualFold(args[0], "INBOX") {
		s.taggedNO(tag, "no such mailbox")
		return
	}
	wanted := strings.Fields(parenContents(args[1]))

	// Snapshot for an accurate count without disturbing session state.
	rows, err := storage.List(0, 0, 0)
	if err != nil {
		s.taggedNO(tag, "STATUS failed")
		return
	}
	total := len(rows)
	unseen := 0
	for _, r := range rows {
		if !r.Read {
			unseen++
		}
	}

	out := []string{}
	for _, w := range wanted {
		switch strings.ToUpper(w) {
		case "MESSAGES":
			out = append(out, "MESSAGES "+strconv.Itoa(total))
		case "RECENT":
			out = append(out, "RECENT 0")
		case "UIDNEXT":
			out = append(out, fmt.Sprintf("UIDNEXT %d", uidNext()))
		case "UIDVALIDITY":
			out = append(out, fmt.Sprintf("UIDVALIDITY %d", uidValidityValue()))
		case "UNSEEN":
			out = append(out, "UNSEEN "+strconv.Itoa(unseen))
		}
	}
	s.writef(`* STATUS "INBOX" (%s)`, strings.Join(out, " "))
	s.taggedOK(tag, "STATUS completed")
}

// cmdUID dispatches UID FETCH / UID STORE / UID SEARCH.
func (s *session) cmdUID(tag, rest string) {
	sp := strings.IndexByte(rest, ' ')
	if sp == -1 {
		s.taggedBAD(tag, "UID requires a sub-command")
		return
	}
	sub := strings.ToUpper(rest[:sp])
	body := strings.TrimLeft(rest[sp+1:], " ")
	switch sub {
	case "FETCH":
		s.cmdFETCH(tag, body, true)
	case "STORE":
		s.cmdSTORE(tag, body, true)
	case "SEARCH":
		s.cmdSEARCH(tag, body, true)
	case "EXPUNGE":
		s.cmdEXPUNGE(tag)
	case "COPY":
		s.cmdCOPY(tag, body, true)
	case "MOVE":
		s.taggedNO(tag, "MOVE not supported (Mailpit has a single mailbox)")
	default:
		s.taggedBAD(tag, "unknown UID sub-command")
	}
}

// cmdFETCH handles FETCH and UID FETCH.
//
//	FETCH 1:5 (UID FLAGS RFC822.SIZE)
//	UID FETCH 1:* (BODY[] FLAGS)
//
// The set of items we honour is intentionally compact — anything we
// don't recognise is silently skipped rather than failing the FETCH so
// real clients (Thunderbird, K-9, mutt) don't get stuck.
func (s *session) cmdFETCH(tag, rest string, useUID bool) {
	if s.state != stateSelected {
		s.taggedNO(tag, "no mailbox selected")
		return
	}
	sp := strings.IndexByte(rest, ' ')
	if sp == -1 {
		s.taggedBAD(tag, "FETCH requires set and items")
		return
	}
	setSpec := rest[:sp]
	itemSpec := strings.TrimLeft(rest[sp+1:], " ")
	items := fetchItemList(itemSpec)

	maxN := len(s.messages)
	if useUID {
		// for UID sets, the upper bound is the highest known UID
		var hi uint32
		for _, m := range s.messages {
			if m.uid > hi {
				hi = m.uid
			}
		}
		maxN = int(hi)
	}
	seqs, err := parseSequenceSet(setSpec, maxN, useUID, s.uidToSeq)
	if err != nil {
		s.taggedBAD(tag, "bad sequence set: "+err.Error())
		return
	}

	for _, seq := range seqs {
		if seq < 1 || seq > len(s.messages) {
			continue
		}
		s.fetchOne(seq, items, useUID)
	}

	verb := "FETCH"
	if useUID {
		verb = "UID FETCH"
	}
	s.taggedOK(tag, verb+" completed")
}

// fetchItemList unwraps "(UID FLAGS BODY[HEADER])" or a single bare item
// like "ENVELOPE" into a flat list of fetch items.
func fetchItemList(s string) []string {
	s = parenContents(strings.TrimSpace(s))
	return tokenize(s)
}

func (s *session) fetchOne(seq int, items []string, useUID bool) {
	m := s.messages[seq-1]

	// If FETCH was issued by UID, the response must include the UID even
	// if the client didn't ask for it (RFC 9051 §6.4.8).
	includeUID := useUID
	for _, it := range items {
		if strings.EqualFold(it, "UID") {
			includeUID = true
		}
	}

	pieces := []string{}
	var rawCache []byte
	getRaw := func() []byte {
		if rawCache != nil {
			return rawCache
		}
		b, err := storage.GetMessageRaw(m.id)
		if err != nil {
			logger.Log().Errorf("[imap] fetch raw %s: %s", m.id, err.Error())
			return nil
		}
		rawCache = b
		return b
	}

	for _, it := range items {
		piece := s.fetchItem(m, it, getRaw)
		if piece != "" {
			pieces = append(pieces, piece)
		}
	}

	if includeUID {
		// avoid duplicate UID
		dup := false
		for _, p := range pieces {
			if strings.HasPrefix(p, "UID ") {
				dup = true
				break
			}
		}
		if !dup {
			pieces = append([]string{fmt.Sprintf("UID %d", m.uid)}, pieces...)
		}
	}

	s.writef("* %d FETCH (%s)", seq, strings.Join(pieces, " "))
}

// fetchItem renders one FETCH item for one message. Returns the wire
// representation (without trailing space) or "" if unsupported.
func (s *session) fetchItem(m sessionMessage, item string, getRaw func() []byte) string {
	upper := strings.ToUpper(item)

	switch {
	case upper == "UID":
		return fmt.Sprintf("UID %d", m.uid)

	case upper == "FLAGS":
		return fmt.Sprintf("FLAGS (%s)", s.flagsList(m.id))

	case upper == "RFC822.SIZE":
		raw := getRaw()
		return fmt.Sprintf("RFC822.SIZE %d", len(raw))

	case upper == "INTERNALDATE":
		t := messageInternalDate(m.id)
		return fmt.Sprintf(`INTERNALDATE "%s"`, t.Format("02-Jan-2006 15:04:05 -0700"))

	case upper == "ENVELOPE":
		return "ENVELOPE " + buildEnvelope(m.id)

	case upper == "BODYSTRUCTURE", upper == "BODY":
		raw := getRaw()
		// Minimal stub — works for plaintext clients and allows others to
		// fall back to BODY[] retrieval.
		return fmt.Sprintf(`%s ("text" "plain" NIL NIL NIL "7bit" %d %d)`,
			upper, len(raw), strings.Count(string(raw), "\n"))

	case upper == "RFC822":
		raw := getRaw()
		return literalSection("RFC822", raw)

	case upper == "RFC822.HEADER":
		hdr, _ := splitHeaderBody(getRaw())
		return literalSection("RFC822.HEADER", hdr)

	case upper == "RFC822.TEXT":
		_, body := splitHeaderBody(getRaw())
		return literalSection("RFC822.TEXT", body)

	case strings.HasPrefix(upper, "BODY[") || strings.HasPrefix(upper, "BODY.PEEK["),
		strings.HasPrefix(upper, "BINARY["), strings.HasPrefix(upper, "BINARY.PEEK["):
		return s.fetchBodySection(m, item, getRaw)
	}

	return ""
}

// fetchBodySection handles BODY[...] / BODY.PEEK[...]. Supported sections:
//
//	BODY[] / BODY.PEEK[]                          → full RFC822 message
//	BODY[HEADER] / BODY.PEEK[HEADER]              → header block
//	BODY[TEXT] / BODY.PEEK[TEXT]                  → body block
//	BODY[HEADER.FIELDS (Subject From ...)]        → selected headers
//	BODY[HEADER.FIELDS.NOT (Subject ...)]         → all but selected headers
//
// Anything else falls back to the full message. Side effect: reading
// without .PEEK auto-marks the message \Seen, mirroring real IMAP.
func (s *session) fetchBodySection(m sessionMessage, item string, getRaw func() []byte) string {
	peek := strings.HasPrefix(strings.ToUpper(item), "BODY.PEEK[") ||
		strings.HasPrefix(strings.ToUpper(item), "BINARY.PEEK[")

	openIdx := strings.IndexByte(item, '[')
	closeIdx := strings.LastIndexByte(item, ']')
	if openIdx < 0 || closeIdx < 0 || closeIdx <= openIdx {
		return ""
	}
	section := strings.ToUpper(strings.TrimSpace(item[openIdx+1 : closeIdx]))

	// Per RFC 9051 §6.4.6, FETCH BODY.PEEK[...] returns its data with
	// the BODY[...] label. Same for BINARY.PEEK[...] → BINARY[...].
	prefix := item[:openIdx]
	switch strings.ToUpper(prefix) {
	case "BODY.PEEK":
		prefix = "BODY"
	case "BINARY.PEEK":
		prefix = "BINARY"
	}
	label := prefix + item[openIdx:closeIdx+1]

	raw := getRaw()
	var data []byte

	switch {
	case section == "":
		data = raw
	case section == "HEADER":
		data, _ = splitHeaderBody(raw)
	case section == "TEXT":
		_, data = splitHeaderBody(raw)
	case strings.HasPrefix(section, "HEADER.FIELDS.NOT"):
		fields := extractFieldList(section[len("HEADER.FIELDS.NOT"):])
		data = filterHeaders(raw, fields, true)
	case strings.HasPrefix(section, "HEADER.FIELDS"):
		fields := extractFieldList(section[len("HEADER.FIELDS"):])
		data = filterHeaders(raw, fields, false)
	default:
		// MIME part fetches like BODY[1] aren't implemented; return
		// empty string rather than failing — clients fall back to BODY[].
		data = []byte{}
	}

	// Mark \Seen unless this was a PEEK
	if !peek && !s.flagsSeen[m.id] && !s.readOnly {
		_ = storage.MarkRead([]string{m.id})
		s.flagsSeen[m.id] = true
	}

	return literalSection(label, data)
}

// literalSection renders a FETCH part using IMAP literal syntax:
//
//	BODY[] {12345}<CRLF>...12345 bytes...
//
// This is the only safe way to ship arbitrary 8-bit content over IMAP.
func literalSection(label string, data []byte) string {
	return fmt.Sprintf("%s {%d}\r\n%s", label, len(data), string(data))
}

// extractFieldList parses "(Subject From To)" or "(\"Subject\" \"From\")"
// into a normalized slice of header field names (uppercased).
func extractFieldList(s string) []string {
	s = strings.TrimSpace(s)
	s = parenContents(s)
	out := []string{}
	for _, t := range tokenize(s) {
		out = append(out, strings.ToUpper(t))
	}
	return out
}

// filterHeaders returns header bytes with only the named fields (or all
// but the named fields if invert is true). The returned blob ends with
// CRLFCRLF, matching what clients expect from BODY[HEADER.FIELDS].
func filterHeaders(raw []byte, fields []string, invert bool) []byte {
	hdr, _ := splitHeaderBody(raw)
	want := map[string]struct{}{}
	for _, f := range fields {
		want[f] = struct{}{}
	}

	var out strings.Builder
	for _, line := range unfoldHeaders(string(hdr)) {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToUpper(strings.TrimSpace(line[:colon]))
		_, in := want[name]
		if invert == in {
			continue
		}
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n")
	return []byte(out.String())
}

// unfoldHeaders splits a header block into one logical header per slice
// element, joining continuation lines (RFC 5322 §2.2.3).
func unfoldHeaders(hdr string) []string {
	lines := strings.Split(strings.ReplaceAll(hdr, "\r\n", "\n"), "\n")
	out := []string{}
	cur := ""
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if ln[0] == ' ' || ln[0] == '\t' {
			cur += " " + strings.TrimSpace(ln)
			continue
		}
		if cur != "" {
			out = append(out, cur)
		}
		cur = ln
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// splitHeaderBody splits a raw RFC822 message into header and body parts
// using the first blank line. The header part includes the trailing
// CRLFCRLF terminator.
func splitHeaderBody(raw []byte) ([]byte, []byte) {
	for i := 0; i < len(raw)-3; i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			return raw[:i+4], raw[i+4:]
		}
		if raw[i] == '\n' && raw[i+1] == '\n' {
			return raw[:i+2], raw[i+2:]
		}
	}
	return raw, []byte{}
}

func messageInternalDate(id string) time.Time {
	// We don't have a separate field for internal date; the message's
	// Created timestamp is the closest equivalent.
	rows, err := storage.List(0, 0, 0)
	if err != nil {
		return time.Now()
	}
	for _, r := range rows {
		if r.ID == id {
			return r.Created
		}
	}
	return time.Now()
}

// buildEnvelope returns an IMAP envelope structure for a message.
//
//	(date subject from sender reply-to to cc bcc in-reply-to message-id)
//
// Each address list is a parenthesised list of (name adl mailbox host).
// We populate what the MessageSummary already has; missing fields become
// NIL.
func buildEnvelope(id string) string {
	rows, err := storage.List(0, 0, 0)
	if err != nil {
		return "NIL"
	}
	var found *storage.MessageSummary
	for i := range rows {
		if rows[i].ID == id {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		return "NIL"
	}

	dateStr := nilOrQuoted(found.Created.Format(time.RFC1123Z))
	subj := nilOrQuoted(found.Subject)
	from := addrList([]*mail.Address{found.From})
	sender := from
	replyTo := addrList(found.ReplyTo)
	if replyTo == "NIL" {
		replyTo = from
	}
	to := addrList(found.To)
	cc := addrList(found.Cc)
	bcc := addrList(found.Bcc)
	inReplyTo := "NIL"
	msgID := nilOrQuoted(found.MessageID)
	if msgID != "NIL" && !strings.HasPrefix(found.MessageID, "<") {
		msgID = fmt.Sprintf(`"<%s>"`, found.MessageID)
	}

	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		dateStr, subj, from, sender, replyTo, to, cc, bcc, inReplyTo, msgID,
	)
}

func addrList(addrs []*mail.Address) string {
	cleaned := []*mail.Address{}
	for _, a := range addrs {
		if a == nil || a.Address == "" {
			continue
		}
		cleaned = append(cleaned, a)
	}
	if len(cleaned) == 0 {
		return "NIL"
	}
	parts := []string{}
	for _, a := range cleaned {
		name := nilOrQuoted(a.Name)
		mailbox, host := splitAddress(a.Address)
		parts = append(parts, fmt.Sprintf("(%s NIL %s %s)",
			name, nilOrQuoted(mailbox), nilOrQuoted(host)))
	}
	return "(" + strings.Join(parts, " ") + ")"
}

func splitAddress(a string) (string, string) {
	at := strings.LastIndexByte(a, '@')
	if at <= 0 {
		return a, ""
	}
	return a[:at], a[at+1:]
}

func nilOrQuoted(s string) string {
	if s == "" {
		return "NIL"
	}
	// IMAP quoted strings escape backslash and double-quote
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// cmdSTORE handles STORE and UID STORE.
//
//	STORE 1:3 +FLAGS (\Seen)
//	UID STORE 5 -FLAGS.SILENT (\Deleted)
//
// We honour \Seen (mapped to storage.Read via MarkRead/MarkUnread) and
// \Deleted (queued for EXPUNGE). All other flags are accepted-but-
// ignored to maximise client compatibility.
func (s *session) cmdSTORE(tag, rest string, useUID bool) {
	if s.state != stateSelected {
		s.taggedNO(tag, "no mailbox selected")
		return
	}
	if s.readOnly {
		s.taggedNO(tag, "mailbox is read-only")
		return
	}
	parts := tokenize(rest)
	if len(parts) < 3 {
		s.taggedBAD(tag, "STORE requires set, op, flags")
		return
	}
	setSpec, op, flagsSpec := parts[0], strings.ToUpper(parts[1]), parts[2]
	silent := strings.HasSuffix(op, ".SILENT")
	op = strings.TrimSuffix(op, ".SILENT")

	maxN := len(s.messages)
	if useUID {
		var hi uint32
		for _, m := range s.messages {
			if m.uid > hi {
				hi = m.uid
			}
		}
		maxN = int(hi)
	}
	seqs, err := parseSequenceSet(setSpec, maxN, useUID, s.uidToSeq)
	if err != nil {
		s.taggedBAD(tag, "bad sequence set: "+err.Error())
		return
	}

	flags := strings.Fields(parenContents(flagsSpec))
	flagSet := map[string]bool{}
	for _, f := range flags {
		flagSet[strings.ToLower(f)] = true
	}

	wantSeen := flagSet[`\seen`]
	wantDel := flagSet[`\deleted`]

	for _, seq := range seqs {
		if seq < 1 || seq > len(s.messages) {
			continue
		}
		m := &s.messages[seq-1]

		// Apply \Seen
		switch op {
		case "FLAGS":
			// replace
			if wantSeen != s.flagsSeen[m.id] {
				if wantSeen {
					_ = storage.MarkRead([]string{m.id})
				} else {
					_ = storage.MarkUnread([]string{m.id})
				}
				s.flagsSeen[m.id] = wantSeen
			}
			m.deleted = wantDel
		case "+FLAGS":
			if wantSeen && !s.flagsSeen[m.id] {
				_ = storage.MarkRead([]string{m.id})
				s.flagsSeen[m.id] = true
			}
			if wantDel {
				m.deleted = true
			}
		case "-FLAGS":
			if wantSeen && s.flagsSeen[m.id] {
				_ = storage.MarkUnread([]string{m.id})
				s.flagsSeen[m.id] = false
			}
			if wantDel {
				m.deleted = false
			}
		default:
			s.taggedBAD(tag, "unknown STORE operation")
			return
		}

		if !silent {
			fl := []string{}
			if s.flagsSeen[m.id] {
				fl = append(fl, `\Seen`)
			}
			if m.deleted {
				fl = append(fl, `\Deleted`)
			}
			if useUID {
				s.writef("* %d FETCH (UID %d FLAGS (%s))", seq, m.uid, strings.Join(fl, " "))
			} else {
				s.writef("* %d FETCH (FLAGS (%s))", seq, strings.Join(fl, " "))
			}
		}
	}

	verb := "STORE"
	if useUID {
		verb = "UID STORE"
	}
	s.taggedOK(tag, verb+" completed")
}

// cmdSEARCH supports a handful of common keys: ALL, UNSEEN, SEEN, NEW,
// RECENT, UID <set>. Unknown keys produce BAD rather than NO so clients
// can degrade quickly.
func (s *session) cmdSEARCH(tag, rest string, useUID bool) {
	if s.state != stateSelected {
		s.taggedNO(tag, "no mailbox selected")
		return
	}
	tokens := tokenize(rest)
	// strip optional CHARSET <name>
	if len(tokens) >= 2 && strings.EqualFold(tokens[0], "CHARSET") {
		tokens = tokens[2:]
	}

	matches := func(m sessionMessage) bool { return true }
	for i := 0; i < len(tokens); i++ {
		switch strings.ToUpper(tokens[i]) {
		case "ALL":
			// no-op
		case "UNSEEN":
			prev := matches
			matches = func(m sessionMessage) bool { return prev(m) && !s.flagsSeen[m.id] }
		case "SEEN":
			prev := matches
			matches = func(m sessionMessage) bool { return prev(m) && s.flagsSeen[m.id] }
		case "NEW", "RECENT":
			// We don't track \Recent — return empty set
			matches = func(m sessionMessage) bool { return false }
		case "UID":
			if i+1 >= len(tokens) {
				s.taggedBAD(tag, "UID requires a set")
				return
			}
			i++
			var hi uint32
			for _, m := range s.messages {
				if m.uid > hi {
					hi = m.uid
				}
			}
			seqs, err := parseSequenceSet(tokens[i], int(hi), true, s.uidToSeq)
			if err != nil {
				s.taggedBAD(tag, "bad UID set")
				return
			}
			allowed := map[uint32]struct{}{}
			for _, seq := range seqs {
				if seq >= 1 && seq <= len(s.messages) {
					allowed[s.messages[seq-1].uid] = struct{}{}
				}
			}
			prev := matches
			matches = func(m sessionMessage) bool {
				if !prev(m) {
					return false
				}
				_, ok := allowed[m.uid]
				return ok
			}
		default:
			s.taggedBAD(tag, "unsupported SEARCH key: "+tokens[i])
			return
		}
	}

	results := []string{}
	for i, m := range s.messages {
		if !matches(m) {
			continue
		}
		if useUID {
			results = append(results, strconv.FormatUint(uint64(m.uid), 10))
		} else {
			results = append(results, strconv.Itoa(i+1))
		}
	}
	s.write("* SEARCH " + strings.Join(results, " "))
	verb := "SEARCH"
	if useUID {
		verb = "UID SEARCH"
	}
	s.taggedOK(tag, verb+" completed")
}

// cmdEXPUNGE deletes messages flagged \Deleted, sending one EXPUNGE
// untagged response per removed message in descending sequence order.
func (s *session) cmdEXPUNGE(tag string) {
	if s.state != stateSelected {
		s.taggedNO(tag, "no mailbox selected")
		return
	}
	if s.readOnly {
		s.taggedNO(tag, "mailbox is read-only")
		return
	}

	// collect sequences to expunge, descending so seq#s remain valid as
	// we emit responses
	type pair struct {
		seq int
		id  string
	}
	var victims []pair
	for i, m := range s.messages {
		if m.deleted {
			victims = append(victims, pair{seq: i + 1, id: m.id})
		}
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].seq > victims[j].seq })

	if len(victims) > 0 {
		ids := make([]string, len(victims))
		for i, v := range victims {
			ids[i] = v.id
		}
		if err := storage.DeleteMessages(ids); err != nil {
			s.taggedNO(tag, "EXPUNGE failed")
			return
		}
		// remove from session.messages and emit responses
		for _, v := range victims {
			s.writef("* %d EXPUNGE", v.seq)
			s.messages = append(s.messages[:v.seq-1], s.messages[v.seq:]...)
		}
	}
	s.taggedOK(tag, "EXPUNGE completed")
}

// cmdCOPY handles COPY and UID COPY. With Mailpit's single-mailbox
// model, the only legal destination is INBOX (a no-op since the source
// mailbox is also INBOX). Anything else gets [TRYCREATE] so the client
// stops trying.
//
// Real IMAP servers verify that every message in the set exists; we do
// the same, but a successful "copy" is just an acknowledgement plus a
// COPYUID response code listing the existing UIDs as both source and
// destination — that is, the message kept its UID because it never
// moved. This keeps clients happy without duplicating storage.
func (s *session) cmdCOPY(tag, rest string, useUID bool) {
	if s.state != stateSelected {
		s.taggedNO(tag, "no mailbox selected")
		return
	}
	parts := tokenize(rest)
	if len(parts) < 2 {
		s.taggedBAD(tag, "COPY requires set and mailbox")
		return
	}
	setSpec, dest := parts[0], parts[1]
	if !strings.EqualFold(dest, "INBOX") {
		s.taggedNO(tag, "[TRYCREATE] no such mailbox")
		return
	}

	maxN := len(s.messages)
	if useUID {
		var hi uint32
		for _, m := range s.messages {
			if m.uid > hi {
				hi = m.uid
			}
		}
		maxN = int(hi)
	}
	seqs, err := parseSequenceSet(setSpec, maxN, useUID, s.uidToSeq)
	if err != nil {
		s.taggedBAD(tag, "bad sequence set: "+err.Error())
		return
	}

	uids := []uint32{}
	for _, seq := range seqs {
		if seq < 1 || seq > len(s.messages) {
			continue
		}
		uids = append(uids, s.messages[seq-1].uid)
	}
	if len(uids) == 0 {
		s.taggedOK(tag, "COPY completed (no messages)")
		return
	}
	uidList := []string{}
	for _, u := range uids {
		uidList = append(uidList, strconv.FormatUint(uint64(u), 10))
	}
	joined := strings.Join(uidList, ",")
	verb := "COPY"
	if useUID {
		verb = "UID COPY"
	}
	s.taggedOK(tag, fmt.Sprintf("[COPYUID %d %s %s] %s completed",
		uidValidityValue(), joined, joined, verb))
}

// cmdCLOSE expunges \Deleted messages without notification and then
// returns the session to the authenticated (un-selected) state.
func (s *session) cmdCLOSE(tag string) {
	if s.state != stateSelected {
		s.taggedNO(tag, "no mailbox selected")
		return
	}
	if !s.readOnly {
		ids := []string{}
		for _, m := range s.messages {
			if m.deleted {
				ids = append(ids, m.id)
			}
		}
		if len(ids) > 0 {
			_ = storage.DeleteMessages(ids)
		}
	}
	s.messages = nil
	s.mailbox = ""
	s.state = stateAuth
	s.taggedOK(tag, "CLOSE completed")
}

// cmdIDLE implements RFC 2177. While idling we forward "new" and
// "delete" events from the in-process events bus as untagged responses.
// The client terminates IDLE by sending DONE on its own line.
func (s *session) cmdIDLE(tag string) {
	if s.state != stateSelected {
		s.taggedNO(tag, "IDLE requires a selected mailbox")
		return
	}

	s.write("+ idling")

	sub := events.Subscribe()
	defer events.Unsubscribe(sub)

	// Read DONE asynchronously so we can also wait on events.
	type readResult struct {
		line string
		err  error
	}
	lineCh := make(chan readResult, 1)
	go func() {
		line, err := s.reader.ReadString('\n')
		lineCh <- readResult{line: line, err: err}
	}()

	// RFC 2177 recommends clients re-IDLE every 29 minutes; allow 30.
	idleDeadline := time.Now().Add(30 * time.Minute)
	s.readDeadline(time.Until(idleDeadline))

	for {
		select {
		case r := <-lineCh:
			if r.err != nil {
				s.idleErr = r.err
				return
			}
			line := strings.TrimRight(r.line, "\r\n")
			if strings.EqualFold(line, "DONE") {
				s.taggedOK(tag, "IDLE terminated")
			} else {
				s.taggedBAD(tag, "expected DONE")
			}
			return

		case e, ok := <-sub:
			if !ok {
				return
			}
			s.handleIdleEvent(e)

		case <-time.After(time.Until(idleDeadline)):
			s.write("* BYE IDLE timeout, please re-issue IDLE")
			s.taggedOK(tag, "IDLE terminated")
			return
		}
	}
}

// handleIdleEvent translates a storage event into an untagged IMAP
// response. We re-snapshot lazily because recomputing the session
// view is cheap relative to a slow client connection.
func (s *session) handleIdleEvent(e events.Event) {
	switch e.Type {
	case "new":
		next, _ := s.snapshot()
		if len(next) > len(s.messages) {
			s.applySnapshot(next)
			s.writef("* %d EXISTS", len(s.messages))
		}
	case "delete", "truncate", "prune":
		next, gone := s.snapshot()
		s.emitExpunges(gone)
		s.applySnapshot(next)
	}
}

// emitExpunges sends one EXPUNGE response per missing UID, using the
// pre-snapshot sequence number. UIDs are processed in descending order
// to keep sequence numbers stable while emitting.
func (s *session) emitExpunges(gone []uint32) {
	if len(gone) == 0 {
		return
	}
	// Build seq lookup against the *pre*-snapshot session.messages
	for _, u := range gone {
		seq, ok := s.uidToSeq(u)
		if !ok {
			continue
		}
		s.writef("* %d EXPUNGE", seq)
		// Remove from current view so subsequent uidToSeq lookups stay
		// consistent with what we've already announced.
		s.messages = append(s.messages[:seq-1], s.messages[seq:]...)
	}
}

// base64Decode is a small wrapper to avoid an import cycle with
// encoding/base64 (we don't need it).
func base64Decode(s string) (string, error) {
	// Standard base64 with padding.
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(s)%4 != 0 {
		return "", errors.New("bad length")
	}
	dec := func(c byte) (int, bool) {
		i := strings.IndexByte(std, c)
		return i, i >= 0
	}
	var out []byte
	for i := 0; i < len(s); i += 4 {
		var v [4]int
		pad := 0
		for j := 0; j < 4; j++ {
			c := s[i+j]
			if c == '=' {
				pad++
				v[j] = 0
				continue
			}
			x, ok := dec(c)
			if !ok {
				return "", errors.New("bad char")
			}
			v[j] = x
		}
		out = append(out, byte((v[0]<<2)|(v[1]>>4)))
		if pad < 2 {
			out = append(out, byte((v[1]<<4)|(v[2]>>2)))
		}
		if pad < 1 {
			out = append(out, byte((v[2]<<6)|v[3]))
		}
	}
	return string(out), nil
}

