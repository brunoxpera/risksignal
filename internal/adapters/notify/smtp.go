package notify

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"
	"net/textproto"
	"strings"

	"github.com/brunoxpera/risksignal/internal/application"
)

// InAppPort is the in-app notification channel (ARCH-004 §6.1): the
// notifications row itself is the surface, rendered by the signal detail
// view in I5b. Delivery therefore has no transport to fail — the row the
// relay handler just inserted is the delivered artefact — so Deliver always
// reports success. It exists as a port so the channel selection is uniform:
// the dispatcher treats in-app like every other channel, and the handler
// records the same delivered receipt.
type InAppPort struct{}

// NewInAppPort returns the in-app channel port.
func NewInAppPort() *InAppPort { return &InAppPort{} }

// Deliver reports the in-app notification as delivered: the persisted row is
// the in-app surface, so there is nothing further to send.
func (p *InAppPort) Deliver(_ context.Context, n application.Notification) (DeliveryReceipt, error) {
	return DeliveryReceipt{Channel: ChannelInApp, Delivered: true, Attempts: 1}, nil
}

// Mailer sends one prepared message (the RFC 5322 bytes) from one envelope
// sender to the envelope recipients. It is the seam over the SMTP transport
// so the adapter is testable without a network: the production
// implementation is NetSMTPMailer (net/smtp), tests substitute a fake or a
// loopback SMTP server.
type Mailer interface {
	Send(from string, to []string, msg []byte) error
}

// NetSMTPMailer is the production Mailer: it drives net/smtp against the
// configured SMTP relay (Mailpit in the local environment, D-004). No
// authentication is used — the local relay is unauthenticated and there is
// no production mail target in I4. Addr is the relay's host:port.
type NetSMTPMailer struct{ Addr string }

// Send delivers msg through net/smtp to the configured relay from the
// envelope sender to the envelope recipients.
func (m NetSMTPMailer) Send(from string, to []string, msg []byte) error {
	return smtp.SendMail(m.Addr, nil, from, to, msg)
}

// SMTPPort is the SMTP notification channel (ARCH-004 §6.1): it renders the
// prepared notification into a minimal RFC 5322 message (content minimised
// per ch. 3.3 — the kind and the signal identity only, never free text or
// secrets) and hands it to the injected Mailer. The From/To envelope is the
// adapter's configuration; the recipient recorded on the notifications row
// is the configured To.
type SMTPPort struct {
	mailer Mailer
	from   string
	to     string
}

// NewSMTPPort assembles the SMTP channel over a Mailer. mailer, from and to
// are mandatory — a missing one is a wiring error reported here.
func NewSMTPPort(mailer Mailer, from, to string) (*SMTPPort, error) {
	if mailer == nil {
		return nil, fmt.Errorf("notify: smtp channel: mailer must not be nil")
	}
	if strings.TrimSpace(from) == "" {
		return nil, fmt.Errorf("notify: smtp channel: from address must not be empty")
	}
	if strings.TrimSpace(to) == "" {
		return nil, fmt.Errorf("notify: smtp channel: to address must not be empty")
	}
	return &SMTPPort{mailer: mailer, from: from, to: to}, nil
}

// Deliver renders n and sends it through the mailer. A permanent SMTP
// rejection (a 5xx reply) is a *PermanentError; a connection failure or a
// 4xx temporary reply is a plain (retryable) error.
func (p *SMTPPort) Deliver(_ context.Context, n application.Notification) (DeliveryReceipt, error) {
	msg := renderSMTPMessage(p.from, p.to, n)
	if err := p.mailer.Send(p.from, []string{p.to}, msg); err != nil {
		receipt := DeliveryReceipt{Channel: ChannelSMTP, Delivered: false, Attempts: 1, Error: err.Error()}
		if isPermanentSMTPError(err) {
			return receipt, Permanent(err)
		}
		return receipt, err
	}
	return DeliveryReceipt{Channel: ChannelSMTP, Delivered: true, Attempts: 1}, nil
}

// renderSMTPMessage builds a minimal RFC 5322 message with CRLF line endings
// (the SMTP wire format). The subject and body carry the event kind and the
// signal id only.
func renderSMTPMessage(from, to string, n application.Notification) []byte {
	var b strings.Builder
	writeHeader(&b, "From", from)
	writeHeader(&b, "To", to)
	writeHeader(&b, "Subject", fmt.Sprintf("[RiskSignal] %s %s", n.Kind, n.SignalID))
	writeHeader(&b, "MIME-Version", "1.0")
	writeHeader(&b, "Content-Type", "text/plain; charset=utf-8")
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "RiskSignal notification\r\nKind: %s\r\nSignal: %s\r\n", n.Kind, n.SignalID)
	return []byte(b.String())
}

// writeHeader appends one header line. Header values are single-line by
// construction (the kind/signal id are enum/id strings, the addresses are
// configuration), so no folding is needed; a newline is stripped defensively
// to keep the message well-formed.
func writeHeader(b *strings.Builder, name, value string) {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", "")
	fmt.Fprintf(b, "%s: %s\r\n", name, value)
}

// isPermanentSMTPError classifies an SMTP send error: a 5xx server reply is
// permanent (the relay rejects the message and retrying cannot help); a 4xx
// reply and every transport error (dial/timeout) are temporary.
func isPermanentSMTPError(err error) bool {
	var protoErr *textproto.Error
	if errors.As(err, &protoErr) {
		return protoErr.Code >= 500 && protoErr.Code < 600
	}
	return false
}
