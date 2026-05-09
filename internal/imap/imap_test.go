package imap

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/axllent/mailpit/config"
	"github.com/axllent/mailpit/internal/auth"
	"github.com/axllent/mailpit/internal/logger"
	"github.com/axllent/mailpit/internal/storage"
	"github.com/jhillyerd/enmime/v2"
)

var testingPort int

// TestIMAP walks the basic protocol: CAPABILITY, LOGIN, SELECT,
// FETCH, STORE, SEARCH, EXPUNGE, LOGOUT — plus the IDLE push notification
// triggered by a storage.Store() call from another goroutine.
func TestIMAP(t *testing.T) {
	setup(t)
	defer storage.Close()

	// pre-seed 3 messages
	insertMessages(t, 3)

	c := dial(t)
	defer c.Close()

	// banner
	expect(t, c, "* OK")

	// CAPABILITY
	send(c, "a CAPABILITY")
	expect(t, c, "* CAPABILITY")
	expect(t, c, "a OK")

	// LOGIN
	send(c, `b LOGIN username password`)
	expect(t, c, "b OK")

	// LIST
	send(c, `c LIST "" "*"`)
	expect(t, c, "* LIST")
	expect(t, c, "c OK")

	// SELECT INBOX
	send(c, "d SELECT INBOX")
	expectContains(t, c, "* 3 EXISTS")
	expectContains(t, c, "[UIDVALIDITY")
	expectContains(t, c, "d OK")

	// FETCH
	send(c, "e FETCH 1 (UID FLAGS RFC822.SIZE)")
	line := readLine(t, c)
	if !strings.Contains(line, "FETCH (UID 1") {
		t.Fatalf("FETCH response missing UID: %q", line)
	}
	expect(t, c, "e OK")

	// SEARCH UNSEEN — all three should be unseen
	send(c, "f SEARCH UNSEEN")
	line = readLine(t, c)
	if !strings.Contains(line, "* SEARCH 1 2 3") {
		t.Fatalf("expected all unseen, got: %q", line)
	}
	expect(t, c, "f OK")

	// STORE \Seen on message 1
	send(c, `g STORE 1 +FLAGS (\Seen)`)
	expectContains(t, c, `FLAGS (\Seen)`)
	expect(t, c, "g OK")

	// Re-search — message 1 should now be SEEN
	send(c, "h SEARCH SEEN")
	line = readLine(t, c)
	if !strings.Contains(line, "* SEARCH 1") {
		t.Fatalf("expected message 1 seen, got: %q", line)
	}
	expect(t, c, "h OK")

	// IDLE — drop into idle, push a message, expect EXISTS untagged
	send(c, "i IDLE")
	expect(t, c, "+ idling")

	insertMessages(t, 1) // triggers events.Publish("new", ...)

	// Read a few lines waiting for EXISTS
	got := readForDuration(t, c, 2*time.Second)
	if !strings.Contains(got, "EXISTS") {
		t.Fatalf("IDLE: expected untagged EXISTS, got: %q", got)
	}

	send(c, "DONE")
	expect(t, c, "i OK")

	// STORE \Deleted + EXPUNGE
	send(c, `j STORE 2 +FLAGS (\Deleted)`)
	expectContains(t, c, `\Deleted`)
	expect(t, c, "j OK")

	send(c, "k EXPUNGE")
	expectContains(t, c, "* 2 EXPUNGE")
	expect(t, c, "k OK")

	// COPY <set> INBOX → [COPYUID ...] OK (no-op, same mailbox).
	// Note: COPYUID rides on the same line as the tagged OK, so one
	// assertion covers both.
	send(c, `m COPY 1 INBOX`)
	line = readLine(t, c)
	if !strings.Contains(line, "[COPYUID") || !strings.HasPrefix(line, "m OK") {
		t.Fatalf("COPY: expected 'm OK [COPYUID ...]', got %q", line)
	}

	// COPY <set> bogus → [TRYCREATE] NO
	send(c, `n COPY 1 OtherFolder`)
	expectContains(t, c, "TRYCREATE")

	// APPEND with non-synchronizing literal (LITERAL+)
	body := "From: a@b.com\r\nTo: c@d.com\r\nSubject: appended\r\n\r\nappend body\r\n"
	send(c, fmt.Sprintf(`o APPEND INBOX (\Seen) {%d+}`, len(body)))
	_, _ = fmt.Fprint(c.conn, body)
	_, _ = fmt.Fprint(c.conn, "\r\n")
	expectContains(t, c, "[APPENDUID")

	// APPEND with synchronizing literal — server must send "+ ..." first
	send(c, fmt.Sprintf(`p APPEND INBOX {%d}`, len(body)))
	expect(t, c, "+ ")
	_, _ = fmt.Fprint(c.conn, body)
	_, _ = fmt.Fprint(c.conn, "\r\n")
	expectContains(t, c, "p OK")

	// MOVE is intentionally not supported — server returns NO
	send(c, "q MOVE 1 INBOX")
	expectContains(t, c, "q NO")

	// LOGOUT
	send(c, "z LOGOUT")
	expect(t, c, "* BYE")
	expect(t, c, "z OK")
}

// TestIMAPBadAuth verifies that LOGIN with the wrong password is rejected
// and that pre-auth commands return NO.
func TestIMAPBadAuth(t *testing.T) {
	setup(t)
	defer storage.Close()

	c := dial(t)
	defer c.Close()
	expect(t, c, "* OK")

	send(c, "a LOGIN username wrongpassword")
	line := readLine(t, c)
	if !strings.Contains(line, "a NO") {
		t.Fatalf("expected NO, got: %q", line)
	}

	send(c, "b SELECT INBOX")
	line = readLine(t, c)
	if !strings.Contains(line, "b NO") {
		t.Fatalf("SELECT before auth should NO, got: %q", line)
	}
}

// helpers ----------------------------------------------------------------

type imapConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (c *imapConn) Close() { _ = c.conn.Close() }

func setup(t *testing.T) {
	t.Helper()
	if err := auth.SetPOP3Auth("username:password"); err != nil {
		t.Fatal(err)
	}
	logger.NoLogging = true
	config.MaxMessages = 0
	config.Database = os.Getenv("MP_DATABASE")

	for {
		testingPort = rand.IntN(2000-1100) + 1100
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", testingPort))
		if err == nil {
			_ = ln.Close()
			break
		}
	}
	config.IMAPListen = fmt.Sprintf("127.0.0.1:%d", testingPort)

	if err := storage.InitDB(); err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteAllMessages(); err != nil {
		t.Fatal(err)
	}
	go Run()
	time.Sleep(500 * time.Millisecond)
}

func dial(t *testing.T) *imapConn {
	t.Helper()
	conn, err := net.Dial("tcp", config.IMAPListen)
	if err != nil {
		t.Fatal(err)
	}
	return &imapConn{conn: conn, reader: bufio.NewReader(conn)}
}

func send(c *imapConn, line string) {
	_, _ = fmt.Fprint(c.conn, line, "\r\n")
}

func readLine(t *testing.T, c *imapConn) string {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %s", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// expect reads lines until one starts with the prefix.
func expect(t *testing.T, c *imapConn, prefix string) {
	t.Helper()
	for i := 0; i < 20; i++ {
		line := readLine(t, c)
		if strings.HasPrefix(line, prefix) {
			return
		}
	}
	t.Fatalf("expected line starting with %q, never saw it", prefix)
}

// expectContains reads lines until one contains the substring.
func expectContains(t *testing.T, c *imapConn, sub string) {
	t.Helper()
	for i := 0; i < 20; i++ {
		line := readLine(t, c)
		if strings.Contains(line, sub) {
			return
		}
	}
	t.Fatalf("expected line containing %q, never saw it", sub)
}

// readForDuration drains everything available within d.
func readForDuration(t *testing.T, c *imapConn, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	var buf strings.Builder
	for time.Now().Before(deadline) {
		_ = c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		line, err := c.reader.ReadString('\n')
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		buf.WriteString(line)
	}
	return buf.String()
}

func insertMessages(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		msg := enmime.Builder().
			From(fmt.Sprintf("F%d", i), fmt.Sprintf("from-%d@example.com", i)).
			Subject(fmt.Sprintf("subject %d", i)).
			Text([]byte(fmt.Sprintf("body %d", i))).
			To(fmt.Sprintf("T%d", i), fmt.Sprintf("to-%d@example.com", i))
		env, err := msg.Build()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := env.Encode(&buf); err != nil {
			t.Fatal(err)
		}
		b := buf.Bytes()
		if _, err := storage.Store(&b, nil); err != nil {
			t.Fatal(err)
		}
	}
}
