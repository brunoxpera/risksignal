package domain

import (
	"fmt"
	"time"
)

// This file owns the SLA value objects of ARCH-004 §4: the reaction-time
// target vocabulary (SLATarget), the injectable duration profile
// (SLATimeProfile) and the clock aggregate (SlaClock) with its
// pause/resume/fulfil/tighten/reset semantics. The application layer
// persists the clocks and reads the injected clock; the domain only computes.

// SLATarget is one reaction-time target of a signal (ch. 6.3, ARCH-004
// §4.1). Exactly these four exist; the sla_clocks.target CHECK mirrors them.
type SLATarget string

// Allowed SLATarget values (ch. 6.3, ARCH-004 §4.1).
const (
	// SLATargetNotification: the active notification is delivered (P1/P2).
	SLATargetNotification SLATarget = "notification"
	// SLATargetAcknowledgement: an analyst explicitly acknowledges (new → in_review).
	SLATargetAcknowledgement SLATarget = "acknowledgement"
	// SLATargetAssessment: a qualified impact assessment is documented.
	SLATargetAssessment SLATarget = "assessment"
	// SLATargetDecision: a disposition is decided.
	SLATargetDecision SLATarget = "decision"
)

// Valid reports whether t is an allowed SLATarget value.
func (t SLATarget) Valid() bool {
	switch t {
	case SLATargetNotification,
		SLATargetAcknowledgement,
		SLATargetAssessment,
		SLATargetDecision:
		return true
	}
	return false
}

// ParseSLATarget parses s into an SLATarget. Unknown values error.
func ParseSLATarget(s string) (SLATarget, error) {
	v := SLATarget(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid SLATarget %q", s)
	}
	return v, nil
}

// SLATimeProfile maps (Priority, SLATarget) to the reaction-time duration
// (ARCH-004 §4.2). A zero/absent entry means "no clock for that target"
// (e.g. P3/P4 get no notification clock — no paging). It is read from
// configuration at composition time so the accelerated test scales only
// durations, never the escalation/status/audit logic (FR-032, NFR-015).
type SLATimeProfile struct {
	durations map[Priority]map[SLATarget]time.Duration
}

// NewSLATimeProfile validates and assembles a profile from explicit
// durations: every key must be a known priority/target and every duration
// must be positive (a zero/absent entry simply means "no clock", so it is
// omitted rather than passed as zero).
func NewSLATimeProfile(durations map[Priority]map[SLATarget]time.Duration) (SLATimeProfile, error) {
	clean := make(map[Priority]map[SLATarget]time.Duration, len(durations))
	for p, targets := range durations {
		if !p.Valid() {
			return SLATimeProfile{}, fmt.Errorf("domain: sla time profile: invalid Priority %q", p)
		}
		clean[p] = make(map[SLATarget]time.Duration, len(targets))
		for t, d := range targets {
			if !t.Valid() {
				return SLATimeProfile{}, fmt.Errorf("domain: sla time profile: invalid SLATarget %q", t)
			}
			if d <= 0 {
				return SLATimeProfile{}, fmt.Errorf("domain: sla time profile: %s/%s duration %s must be positive", p, t, d)
			}
			clean[p][t] = d
		}
	}
	return SLATimeProfile{durations: clean}, nil
}

// DefaultSLATimeProfile returns the ch. 9.4 / ARCH-004 §4.2 default
// durations (P1 5m/15m/60m/4h, P2 15m/1h/4h/24h, P3 -/24h/72h/-,
// P4 -/-/168h/-). P4's "weekly review" is the 168h assessment clock; P3/P4
// carry no decision clock and only P1/P2 page (notification clock).
func DefaultSLATimeProfile() SLATimeProfile {
	return SLATimeProfile{durations: map[Priority]map[SLATarget]time.Duration{
		PriorityP1: {
			SLATargetNotification:    5 * time.Minute,
			SLATargetAcknowledgement: 15 * time.Minute,
			SLATargetAssessment:      60 * time.Minute,
			SLATargetDecision:        4 * time.Hour,
		},
		PriorityP2: {
			SLATargetNotification:    15 * time.Minute,
			SLATargetAcknowledgement: 1 * time.Hour,
			SLATargetAssessment:      4 * time.Hour,
			SLATargetDecision:        24 * time.Hour,
		},
		PriorityP3: {
			SLATargetAcknowledgement: 24 * time.Hour,
			SLATargetAssessment:      72 * time.Hour,
		},
		PriorityP4: {
			SLATargetAssessment: 168 * time.Hour,
		},
	}}
}

// Duration returns the reaction-time duration for the (priority, target)
// pair; zero means no clock is defined for that pair.
func (p SLATimeProfile) Duration(priority Priority, target SLATarget) time.Duration {
	if p.durations == nil {
		return 0
	}
	return p.durations[priority][target]
}

// Defined reports whether a clock exists for the (priority, target) pair.
func (p SLATimeProfile) Defined(priority Priority, target SLATarget) bool {
	return p.Duration(priority, target) > 0
}

// Targets returns the targets that have a clock at the priority, in the
// canonical notification→acknowledgement→assessment→decision order.
func (p SLATimeProfile) Targets(priority Priority) []SLATarget {
	order := []SLATarget{SLATargetNotification, SLATargetAcknowledgement, SLATargetAssessment, SLATargetDecision}
	var out []SLATarget
	for _, t := range order {
		if p.Defined(priority, t) {
			out = append(out, t)
		}
	}
	return out
}

// SlaClock is one running reaction-time clock of a signal (ARCH-004 §4.1,
// ch. 7.1 sla_clocks). started_at/deadline_at freeze the target at creation;
// fulfilled_at marks the target met (zero = open); paused_seconds accumulates
// the pause duration and paused_at is the current pause start (zero = not
// paused) so the effective deadline can be computed during a pause.
//
// EffectiveDeadline is deadline_at + paused_seconds + (now − paused_at if
// paused): pauses are not retroactive (ch. 9.4) and the remaining time is
// frozen while paused. A fulfilled clock is never re-opened by fulfil.
type SlaClock struct {
	ID       string
	SignalID string
	Target   SLATarget

	StartedAt   time.Time
	DeadlineAt  time.Time
	FulfilledAt time.Time

	PausedSeconds int64
	PausedAt      time.Time
}

// NewSlaClock assembles a clock for the (priority, target) pair at instant
// now: started_at = now, deadline_at = now + duration. A pair without a
// defined duration is an error — a clock is never created for a target that
// has no SLA (e.g. P3/P4 notification).
func NewSlaClock(id, signalID string, target SLATarget, priority Priority, profile SLATimeProfile, now time.Time) (SlaClock, error) {
	if id == "" {
		return SlaClock{}, fmt.Errorf("domain: sla clock id must not be empty")
	}
	if signalID == "" {
		return SlaClock{}, fmt.Errorf("domain: sla clock signal_id must not be empty")
	}
	if !target.Valid() {
		return SlaClock{}, fmt.Errorf("domain: invalid SLATarget %q", target)
	}
	if now.IsZero() {
		return SlaClock{}, fmt.Errorf("domain: sla clock start instant must not be zero")
	}
	d := profile.Duration(priority, target)
	if d <= 0 {
		return SlaClock{}, fmt.Errorf("domain: no %s sla clock defined for priority %s", target, priority)
	}
	return SlaClock{
		ID:         id,
		SignalID:   signalID,
		Target:     target,
		StartedAt:  now,
		DeadlineAt: now.Add(d),
	}, nil
}

// Paused reports whether the clock is currently paused.
func (c SlaClock) Paused() bool { return !c.PausedAt.IsZero() }

// Fulfilled reports whether the target has been met.
func (c SlaClock) Fulfilled() bool { return !c.FulfilledAt.IsZero() }

// EffectiveDeadline returns the deadline with the accumulated pauses and,
// while paused, the currently elapsed pause added — the deadline the breach
// scan compares against.
func (c SlaClock) EffectiveDeadline(now time.Time) time.Time {
	d := c.DeadlineAt.Add(time.Duration(c.PausedSeconds) * time.Second)
	if c.Paused() {
		d = d.Add(now.Sub(c.PausedAt))
	}
	return d
}

// Overdue reports whether an open clock is past its effective deadline at
// instant now.
func (c SlaClock) Overdue(now time.Time) bool {
	return !c.Fulfilled() && now.After(c.EffectiveDeadline(now))
}

// Pause starts a pause at instant now (mandatory reason/actor are audit
// events, not clock state). A fulfilled or already-paused clock cannot be
// paused.
func (c SlaClock) Pause(now time.Time) (SlaClock, error) {
	if c.Fulfilled() {
		return SlaClock{}, fmt.Errorf("domain: sla clock %s is already fulfilled", c.ID)
	}
	if c.Paused() {
		return SlaClock{}, fmt.Errorf("domain: sla clock %s is already paused", c.ID)
	}
	if now.IsZero() {
		return SlaClock{}, fmt.Errorf("domain: sla clock pause: instant must not be zero")
	}
	c.PausedAt = now
	return c, nil
}

// Resume ends the active pause at instant now, accumulating the paused
// duration into PausedSeconds and clearing the pause start. A clock that is
// not paused cannot be resumed; now must not precede the pause start.
func (c SlaClock) Resume(now time.Time) (SlaClock, error) {
	if !c.Paused() {
		return SlaClock{}, fmt.Errorf("domain: sla clock %s is not paused", c.ID)
	}
	if now.Before(c.PausedAt) {
		return SlaClock{}, fmt.Errorf("domain: sla clock %s resume %s precedes pause start %s", c.ID, now, c.PausedAt)
	}
	c.PausedSeconds += int64(now.Sub(c.PausedAt) / time.Second)
	c.PausedAt = time.Time{}
	return c, nil
}

// Fulfil marks the target met at instant now. It is idempotent: fulfilling
// an already-fulfilled clock returns it unchanged (a fulfilled clock is
// never re-opened). A paused clock must be resumed first.
func (c SlaClock) Fulfil(now time.Time) (SlaClock, error) {
	if c.Fulfilled() {
		return c, nil
	}
	if c.Paused() {
		return SlaClock{}, fmt.Errorf("domain: sla clock %s is paused (resume before fulfilling)", c.ID)
	}
	if now.IsZero() {
		return SlaClock{}, fmt.Errorf("domain: sla clock fulfil: instant must not be zero")
	}
	c.FulfilledAt = now
	return c, nil
}

// Tighten shortens the deadline on a priority upgrade: the deadline becomes
// now + d, keeping started_at, but only when that is earlier than the
// current deadline (ARCH-004 §4.3). A longer/equal new duration leaves the
// clock untouched; a fulfilled clock cannot be tightened.
func (c SlaClock) Tighten(now time.Time, d time.Duration) (SlaClock, error) {
	if c.Fulfilled() {
		return SlaClock{}, fmt.Errorf("domain: sla clock %s is already fulfilled", c.ID)
	}
	if d <= 0 {
		return SlaClock{}, fmt.Errorf("domain: sla clock tighten: duration must be positive")
	}
	if now.IsZero() {
		return SlaClock{}, fmt.Errorf("domain: sla clock tighten: instant must not be zero")
	}
	if tightened := now.Add(d); tightened.Before(c.DeadlineAt) {
		c.DeadlineAt = tightened
	}
	return c, nil
}

// Reset restarts the clock on a reopen (→ in_review, ARCH-004 §4.3):
// started_at = now, deadline_at = now + d, fulfilled_at cleared, the pause
// counters zeroed. The prior clock history lives in the audit, not here.
func (c SlaClock) Reset(now time.Time, d time.Duration) (SlaClock, error) {
	if d <= 0 {
		return SlaClock{}, fmt.Errorf("domain: sla clock reset: duration must be positive")
	}
	if now.IsZero() {
		return SlaClock{}, fmt.Errorf("domain: sla clock reset: instant must not be zero")
	}
	c.StartedAt = now
	c.DeadlineAt = now.Add(d)
	c.FulfilledAt = time.Time{}
	c.PausedSeconds = 0
	c.PausedAt = time.Time{}
	return c, nil
}
