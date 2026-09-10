package notify

// Tests of the SMTP channel (smtp.go): the message rendering and error
// classification against a fake Mailer, and the end-to-end accept/reject
// behaviour of the production NetSMTPMailer against a minimal loopback SMTP
// server (network-free: the listener binds 127.0.0.1 on an ephemeral port).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
)

// recordingMailer captures the last message and returns a fixed error.
type recordingMailer struct {
	from, to string
	msg      []byte
	err      error
	calls    int
}

func (m *recordingMailer) Send(from string, to []string, msg []byte) error {
	m.calls++
	m.from = from
	m.to = strings.Join(to, ",")
	m.msg = msg
	return m.err
}

func TestSMTPPortRendersAndDelivers(t *testing.T) {
	mailer := &recordingMailer{}
	port, err := NewSMTPPort(mailer, "risk@example.test", "analyst@example.test")
	if err != nil {
		t.Fatalf("NewSMTPPort: %v", err)
	}

	receipt, err := port.Deliver(context.Background(), application.Notification{
		Channel: "smtp", Kind: "signal.created", SignalID: "sig-1",
	})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !receipt.Delivered {
		t.Fatalf("receipt = %+v, want delivered", receipt)
	}
	if mailer.calls != 1 || mailer.from != "risk@example.test" || mailer.to != "analyst@example.test" {
		t.Fatalf("mailer envelope = %q -> %q (calls %d)", mailer.from, mailer.to, mailer.calls)
	}
	msg := string(mailer.msg)
	for _, want := range []string{"From: risk@example.test\r\n", "To: analyst@example.test\r\n", "Subject: [RiskSignal] signal.created sig-1\r\n", "\r\n\r\n"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestSMTPPortClassifiesPermanentAndTemporary(t *testing.T) {
	mailer := &recordingMailer{err: &textproto.Error{Code: 550, Msg: "mailbox unavailable"}}
	port, _ := NewSMTPPort(mailer, "risk@example.test", "analyst@example.test")
	_, err := port.Deliver(context.Background(), application.Notification{Channel: "smtp"})
	if !IsPermanent(err) {
		t.Fatalf("5xx reply error = %v, want permanent", err)
	}

	mailer.err = errors.New("dial tcp: connection refused")
	_, err = port.Deliver(context.Background(), application.Notification{Channel: "smtp"})
	if err == nil || IsPermanent(err) {
		t.Fatalf("transport error = %v, want a temporary (non-permanent) error", err)
	}

	mailer.err = &textproto.Error{Code: 451, Msg: "try again later"}
	_, err = port.Deliver(context.Background(), application.Notification{Channel: "smtp"})
	if err == nil || IsPermanent(err) {
		t.Fatalf("4xx reply error = %v, want a temporary error", err)
	}
}

func TestSMTPPortRequiresConfiguration(t *testing.T) {
	if _, err := NewSMTPPort(nil, "a@b", "c@d"); err == nil {
		t.Error("nil mailer accepted")
	}
	if _, err := NewSMTPPort(&recordingMailer{}, "", "c@d"); err == nil {
		t.Error("empty from accepted")
	}
	if _, err := NewSMTPPort(&recordingMailer{}, "a@b", ""); err == nil {
		t.Error("empty to accepted")
	}
}

// TestNetSMTPMailerAgainstLoopbackServer proves the production Mailer end to
// end against a minimal SMTP server: an accepting server yields a delivered
// receipt, a server that rejects the recipient yields a permanent error.
func TestNetSMTPMailerAgainstLoopbackServer(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		addr := startSMTPServer(t, false)
		port, err := NewSMTPPort(NetSMTPMailer{Addr: addr}, "risk@example.test", "analyst@example.test")
		if err != nil {
			t.Fatalf("NewSMTPPort: %v", err)
		}
		receipt, err := port.Deliver(context.Background(), application.Notification{Channel: "smtp", Kind: "signal.created", SignalID: "sig-1"})
		if err != nil {
			t.Fatalf("Deliver against accepting server: %v", err)
		}
		if !receipt.Delivered {
			t.Fatalf("receipt = %+v, want delivered", receipt)
		}
	})

	t.Run("reject", func(t *testing.T) {
		addr := startSMTPServer(t, true)
		port, err := NewSMTPPort(NetSMTPMailer{Addr: addr}, "risk@example.test", "analyst@example.test")
		if err != nil {
			t.Fatalf("NewSMTPPort: %v", err)
		}
		receipt, err := port.Deliver(context.Background(), application.Notification{Channel: "smtp", Kind: "signal.created", SignalID: "sig-1"})
		if !IsPermanent(err) {
			t.Fatalf("Deliver against rejecting server error = %v, want permanent", err)
		}
		if receipt.Delivered || receipt.Error == "" {
			t.Fatalf("receipt = %+v, want a failed receipt with the error text", receipt)
		}
	})
}

// startSMTPServer starts a minimal SMTP server on a loopback ephemeral port
// and returns its host:port. When reject is true every RCPT TO is refused
// with a 550 reply (the permanent-rejection path); otherwise messages are
// accepted.
func startSMTPServer(t *testing.T, reject bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSMTP(conn, reject)
		}
	}()
	return ln.Addr().String()
}

// serveSMTP speaks just enough SMTP for net/smtp.SendMail: the greeting,
// EHLO/HELO, MAIL FROM, RCPT TO (accept or 550), DATA and QUIT.
func serveSMTP(conn net.Conn, reject bool) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(s string) { fmt.Fprintf(w, "%s\r\n", s); _ = w.Flush() }

	write("220 risksignal-test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			write("250-risksignal-test")
			write("250 OK")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			write("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			if reject {
				write("550 mailbox unavailable")
			} else {
				write("250 OK")
			}
		case cmd == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
			}
			write("250 OK queued")
		case cmd == "QUIT":
			write("221 Bye")
			return
		default:
			write("250 OK")
		}
	}
}
