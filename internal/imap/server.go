// Package imap is a minimal IMAP4rev1 server for Mailpit.
//
// Scope: a single hard-coded INBOX, no folder hierarchy, no APPEND, no
// COPY/MOVE. Just enough surface to let real mail clients (Thunderbird,
// K-9, mutt, neomutt, evolution) connect, receive new messages in real
// time via IDLE, mark them \Seen, and EXPUNGE if needed.
//
// References:
//   - RFC 9051 — IMAP4rev2 (we implement the rev1 subset)
//   - RFC 3501 — IMAP4rev1
//   - RFC 2177 — IMAP IDLE extension
//   - RFC 4959 — IMAP SASL-IR
//
// Authentication and TLS configuration mirror the POP3 server: the same
// htpasswd-style credentials are used, and the same optional cert/key
// pair gates implicit TLS.
package imap

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/axllent/mailpit/config"
	"github.com/axllent/mailpit/internal/auth"
	"github.com/axllent/mailpit/internal/logger"
)

// Run starts the IMAP server if enabled and authentication is configured.
// It blocks; callers should invoke it in a goroutine.
func Run() {
	if auth.POP3Credentials == nil || config.IMAPListen == "" {
		// IMAP is disabled when authentication isn't configured. We
		// reuse POP3 credentials so a single htpasswd file unlocks both.
		return
	}

	var listener net.Listener
	var err error

	if config.IMAPTLSCert != "" {
		cer, err2 := tls.LoadX509KeyPair(config.IMAPTLSCert, config.IMAPTLSKey)
		if err2 != nil {
			logger.Log().Errorf("[imap] %s", err2.Error())
			return
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", config.IMAPListen, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", config.IMAPListen)
	}

	if err != nil {
		logger.Log().Errorf("[imap] %s", err.Error())
		return
	}

	logger.Log().Infof("[imap] starting on %s", config.IMAPListen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Log().Errorf("[imap] accept error: %s", err.Error())
			continue
		}
		go handleClient(conn)
	}
}

// handleClient runs the IMAP state machine for one connection.
func handleClient(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Log().Debugf("[imap] close: %s", err.Error())
		}
	}()

	s := newSession(conn)
	logger.Log().Debugf("[imap] connection opened by %s", conn.RemoteAddr().String())

	// Greeting includes the configured label so multiple mailpit
	// instances behind a proxy are distinguishable.
	serverName := "Mailpit"
	if config.Label != "" {
		serverName = fmt.Sprintf("Mailpit (%s)", config.Label)
	}
	s.writef("* OK %s IMAP4rev1 ready", serverName)

	// 30 minutes of idle time before the server gives up. IDLE
	// temporarily extends this; ordinary commands reset on each loop.
	const idleTimeout = 30 * time.Minute

	for {
		s.readDeadline(idleTimeout)
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				logger.Log().Debugf("[imap] client disconnected: %s", conn.RemoteAddr().String())
			} else {
				logger.Log().Debugf("[imap] read error: %s", err.Error())
			}
			return
		}

		if !s.dispatch(line) {
			return
		}
		if s.state == stateLogout {
			return
		}
	}
}
