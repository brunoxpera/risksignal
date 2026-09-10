package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// This file owns the two remaining I4 application use cases (WP-4.04b /
// DEV-077): PublishPriorityRules (the versioned ruleset snapshot publication,
// ARCH-004 §1) and RecomputePriority (the targeted, changed-only priority
// recompute, ARCH-004 §5 / ch. 9.5). Both follow the house command shape —
// validate, load, apply the domain rule, then inside one transaction persist
// the state change, append the audit event and enqueue the outbox event (one
// command, one transaction, ch. 5.1). The persistence deps are the ports of
// ports.go; the concrete adapters are the DEV-073/DEV-077 postgres
// repositories. The `priority.recompute` job handler and its relay
// registration are WP-4.05, not here.

// Event types and audit vocabulary of the priority use cases (ARCH-004 §1/§5).
const (
	// EventTypePriorityRulesPublished records the publication of a new
	// priority-rules snapshot.
	EventTypePriorityRulesPublished = "priority_rules.published"
	// EventTypeSignalPriorityRecomputed records a compute-only priority
	// change written by RecomputePriority (the row write + its audit).
	EventTypeSignalPriorityRecomputed = "signal.priority_recomputed"
	// EventTypeSignalReopenProposed records that a closed signal's recomputed
	// priority differs — the visible, auditable reopen proposal (ch. 9.5; the
	// reopen itself is a human decision).
	EventTypeSignalReopenProposed = "signal.reopen_proposed"
	// AuditAggregatePriorityRules is the aggregate type of the priority_rules
	// snapshot audit rows (the published ruleset).
	AuditAggregatePriorityRules = "priority_rules"

	// EventTypePriorityRecompute is the outbox type of the priority.recompute
	// job (ARCH-004 §5, ch. 14.1): a targeted per-signal recompute the worker
	// relay handler consumes. It is enqueued by a ruleset publish (batched
	// over the open signals) and by the matching.recompute fan-in (per
	// affected signal).
	EventTypePriorityRecompute = "priority.recompute"
	// ActorPriorityRecompute is the system principal of the priority.recompute
	// handler's audit rows.
	ActorPriorityRecompute = "priority-recompute"
)

// PriorityRecomputePayload is the outbox payload of one priority.recompute
// job (ARCH-004 §5): the signal the recompute targets, the rule version the
// enqueue read (the effective snapshot at enqueue time) and the canonical
// input_hash the dedupe key carries (the hash of the signal's stored
// factor-set + rule version at enqueue). It mirrors the house envelope and
// carries identities/hashes only — never a secret (ch. 3.3, TR-013). The
// handler drives RecomputePriority, which rebuilds the factors fresh and
// recomputes its own input hash; the payload hash is the job identity.
type PriorityRecomputePayload struct {
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	SignalID      string    `json:"signal_id"`
	RuleVersion   string    `json:"rule_version"`
	InputHash     string    `json:"input_hash"`
	OccurredAt    time.Time `json:"occurred_at"`
	CorrelationID string    `json:"correlation_id"`
}

// PriorityRecomputeDedupeKey is the outbox dedupe key of one
// priority.recompute job (ARCH-004 §5): "priority.recompute:" namespacing the
// key (the outbox UQ is global across job types), then the signal id, the
// rule version and the canonical input_hash. A re-enqueue with identical
// inputs derives the same key and is a no-op at the schema level; a changed
// factor-set or rule version derives a new key and enqueues a fresh job.
func PriorityRecomputeDedupeKey(signalID, ruleVersion, inputHash string) string {
	return EventTypePriorityRecompute + ":" + signalID + ":" + ruleVersion + ":" + inputHash
}

// PriorityInputHash is the canonical SHA-256 of one recompute input: the
// effective rule version plus the canonical factor-set (the stable struct
// field order of domain.PriorityFactors). It is the input_hash of the
// priority.recompute dedupe key (ARCH-004 §5): a re-run with identical inputs
// produces the same hash, so the job layer can treat it as a no-op. Deep-
// equal factor-sets therefore always derive the same key.
func PriorityInputHash(ruleVersion string, f domain.PriorityFactors) (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("marshal priority factors: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(ruleVersion))
	h.Write([]byte{0x1f}) // unit separator: version and factors cannot collide
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PublishPriorityRulesInput is the PublishPriorityRules command (ARCH-004 §1):
// publish a new ruleset snapshot at version = MAX(version)+1 from the domain
// seed definitions. Reason and Actor are mandatory and are stamped on every
// row and on the audit event.
type PublishPriorityRulesInput struct {
	Reason        string
	Actor         Actor
	CorrelationID string
}

// PublishPriorityRulesResult carries the new effective version, its string
// form and the command's correlation id.
type PublishPriorityRulesResult struct {
	Version       int
	RuleVersion   string
	CorrelationID string
}

// RecomputePriorityInput is the RecomputePriority command (ARCH-004 §5): the
// targeted per-signal recompute a scheduler/job drives (WP-4.05). Actor is
// the audit principal; the recompute reads nothing else from the caller — the
// effective ruleset and the fresh factor set are resolved internally.
type RecomputePriorityInput struct {
	SignalID      string
	Actor         Actor
	CorrelationID string
}

// RecomputePriorityResult is the outcome of one recompute: the recomputed
// computed priority, the rule version and canonical input hash it ran under,
// whether a row write happened (Changed — false on an identical recompute)
// and whether a reopen proposal was emitted for a closed signal.
type RecomputePriorityResult struct {
	SignalID       string
	Priority       domain.Priority
	RuleVersion    string
	InputHash      string
	Changed        bool
	ReopenProposed bool
}

// priorityRulesPublishedPayload is the outbox payload of a ruleset publish:
// the envelope of the house style plus the published version and its rule
// ids. Identity/enum only — no free text.
type priorityRulesPublishedPayload struct {
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	Version       int       `json:"version"`
	RuleVersion   string    `json:"rule_version"`
	RuleIDs       []string  `json:"rule_ids"`
	OccurredAt    time.Time `json:"occurred_at"`
	CorrelationID string    `json:"correlation_id"`
}

// PublishPriorityRules publishes a new ruleset snapshot (ARCH-004 §1): it
// builds the P1–P4 snapshot from the domain seed definitions, then — inside
// one transaction — writes the whole snapshot at version = MAX(version)+1,
// appends the audit event and enqueues the outbox event. The command is
// admin/audited; reason and actor are mandatory.
func (s *Service) PublishPriorityRules(ctx context.Context, in PublishPriorityRulesInput) (PublishPriorityRulesResult, error) {
	const op = "publish_priority_rules"

	if strings.TrimSpace(in.Reason) == "" {
		return PublishPriorityRulesResult{}, Validationf(op, "publish reason must not be empty")
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return PublishPriorityRulesResult{}, err
	}

	rules := publishSeedRules(in.Reason, actor.ID)
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var version int
	err = s.runTx(ctx, func(tx Tx) error {
		v, err := s.priorityRules.Publish(ctx, tx, rules, now, in.Reason, actor.ID, now)
		if err != nil {
			return err
		}
		version = v
		ruleVersion, err := domain.PriorityRuleVersion(v)
		if err != nil {
			return InfraError(op, err)
		}
		after, err := priorityRulesSnapshot(v, ruleVersion, rules)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendRulesAudit(ctx, tx, EventTypePriorityRulesPublished, actor, correlationID, now, after); err != nil {
			return err
		}
		payload, err := json.Marshal(priorityRulesPublishedPayload{
			EventID:       uuid.New(),
			Type:          EventTypePriorityRulesPublished,
			Version:       v,
			RuleVersion:   ruleVersion,
			RuleIDs:       ruleIDs(rules),
			OccurredAt:    now,
			CorrelationID: correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypePriorityRulesPublished,
			Payload:     payload,
			DedupeKey:   EventTypePriorityRulesPublished + ":" + ruleVersion,
			AvailableAt: now,
			CreatedAt:   now,
		}); err != nil {
			return err
		}
		// The §5 fan-in: a rule-version publish enqueues a batched recompute
		// over all open signals, on the very transaction that published the
		// snapshot — a rolled-back publish enqueues nothing. The jobs carry
		// the new rule version; the handler rebuilds each signal's factors
		// fresh (changed-only persist keeps an identical recompute a no-op).
		_, err = s.enqueueOpenPriorityRecomputes(ctx, tx, ruleVersion, correlationID, now)
		return err
	})
	if err != nil {
		return PublishPriorityRulesResult{}, err
	}
	ruleVersion, err := domain.PriorityRuleVersion(version)
	if err != nil {
		return PublishPriorityRulesResult{}, InfraError(op, err)
	}
	return PublishPriorityRulesResult{Version: version, RuleVersion: ruleVersion, CorrelationID: correlationID}, nil
}

// RecomputePriority recomputes the computed priority of one signal (ARCH-004
// §5, ch. 9.5): it rebuilds the factor set fresh (match method→confidence per
// ADR-015, KEV/CVSS from evidence, EPSS percentile from epss_current,
// criticality/exposure from the owning asset), evaluates the effective
// ruleset and persists the result only when
// the factor-set, the rule version or the evaluated result actually changed —
// an identical recompute writes nothing (no row write, no audit, no version
// bump). For an overridden signal only the preserved auto_priority is updated
// (the human decision always wins, §3). A closed signal is never silently
// changed: the recompute skips it and, when the recomputed priority differs,
// emits a `signal.reopen_proposed` outbox event exactly once.
func (s *Service) RecomputePriority(ctx context.Context, in RecomputePriorityInput) (RecomputePriorityResult, error) {
	const op = "recompute_priority"

	if in.SignalID == "" {
		return RecomputePriorityResult{}, Validationf(op, "signal_id must not be empty")
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return RecomputePriorityResult{}, err
	}

	current, err := s.signalTriage.GetRiskSignal(ctx, in.SignalID)
	if err != nil {
		return RecomputePriorityResult{}, err
	}

	// The effective ruleset: a version < 1 means no snapshot has been
	// published, so there is nothing to evaluate — the recompute is a no-op
	// and never demotes an I1b-stamped signal to the P4 terminal default.
	version, err := s.priorityRules.EffectiveVersion(ctx)
	if err != nil {
		return RecomputePriorityResult{}, err
	}
	if version < 1 {
		return RecomputePriorityResult{SignalID: in.SignalID}, nil
	}
	rules, err := s.priorityRules.Effective(ctx)
	if err != nil {
		return RecomputePriorityResult{}, err
	}
	if len(rules) == 0 {
		return RecomputePriorityResult{SignalID: in.SignalID}, nil
	}
	ruleVersion, err := domain.PriorityRuleVersion(version)
	if err != nil {
		return RecomputePriorityResult{}, InfraError(op, err)
	}

	rebuild, err := s.factorSource.Rebuild(ctx, in.SignalID)
	if err != nil {
		return RecomputePriorityResult{}, err
	}
	factors := rebuild.Factors
	if err := factors.Validate(); err != nil {
		return RecomputePriorityResult{}, ValidationError(op, err)
	}
	newPriority, err := domain.EvaluatePriority(rules, factors)
	if err != nil {
		return RecomputePriorityResult{}, InfraError(op, err)
	}
	inputHash, err := PriorityInputHash(ruleVersion, factors)
	if err != nil {
		return RecomputePriorityResult{}, InfraError(op, err)
	}
	result := RecomputePriorityResult{
		SignalID:    in.SignalID,
		Priority:    newPriority,
		RuleVersion: ruleVersion,
		InputHash:   inputHash,
	}

	// The computed value before the recompute: the effective priority for a
	// purely computed signal, the preserved auto_priority for an overridden
	// one (ADR-015 mirror).
	computedBefore := current.Priority
	if current.Overridden() {
		computedBefore = *current.AutoPriority
	}

	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	// Closed signals are never silently changed (ch. 9.5): recompute skips
	// them and, when the recomputed priority would differ from the computed
	// one, emits a reopen *proposal* (reopen is a human decision).
	if current.Status.IsClosed() {
		if newPriority == computedBefore {
			return result, nil
		}
		proposed, err := s.proposeReopen(ctx, current, actor, rebuild.CVEID, computedBefore, newPriority, ruleVersion, inputHash, correlationID, now)
		if err != nil {
			return RecomputePriorityResult{}, err
		}
		result.ReopenProposed = proposed
		return result, nil
	}

	// Changed-only persist (ch. 9.5): an identical recompute writes nothing.
	if factors == current.Factors && ruleVersion == current.RuleVersion && newPriority == computedBefore {
		return result, nil
	}

	if err := s.runTx(ctx, func(tx Tx) error {
		row, err := s.signalTriage.RecomputePriority(ctx, tx, in.SignalID, newPriority, ruleVersion, factors)
		if err != nil {
			return err
		}
		before, err := signalStateSnapshot(current, "")
		if err != nil {
			return InfraError(op, err)
		}
		after, err := signalStateSnapshot(row, "priority recompute "+ruleVersion)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalPriorityRecomputed, current.ID, actor, correlationID, now, before, after); err != nil {
			return err
		}
		// The ARCH-004 §4.3 priority-upgrade clock treatment: a recompute that
		// moves the *effective* priority (a purely-computed signal) syncs the
		// clocks the new priority defines — it creates the missing ones and
		// tightens the existing ones whose new deadline is earlier, auditing
		// every mutation. An overridden signal keeps its effective priority
		// (only auto_priority moves, §3), so its clocks are left alone; an
		// identical recompute never reaches this transaction at all
		// (changed-only persist above), and a downgrade the new priority is not
		// a superset of simply has no missing target to create.
		if row.Priority != current.Priority {
			if err := s.applyUpgradeClocks(ctx, tx, row.ID, row.Priority, actor, correlationID, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return RecomputePriorityResult{}, err
	}
	result.Changed = true
	return result, nil
}

// proposeReopen emits the closed-signal reopen proposal of one recompute
// (ARCH-004 §5). The outbox dedupe key is content-based
// (type:signal:ruleVersion:inputHash), so re-running the recompute over an
// unchanged closed signal is a no-op — the proposal is emitted exactly once.
// The audit event is appended only when the outbox row is actually written.
func (s *Service) proposeReopen(ctx context.Context, current domain.RiskSignal, actor Actor, cveID string, from, to domain.Priority, ruleVersion, inputHash, correlationID string, now time.Time) (bool, error) {
	const op = "recompute_priority"
	dedupeKey := EventTypeSignalReopenProposed + ":" + current.ID + ":" + ruleVersion + ":" + inputHash

	proposed := false
	err := s.runTx(ctx, func(tx Tx) error {
		exists, err := s.outbox.ExistsDedupeKey(ctx, tx, dedupeKey)
		if err != nil {
			return err
		}
		if exists {
			return nil // already proposed — exactly once
		}
		after, err := reopenProposalSnapshot(current, cveID, from, to, ruleVersion, inputHash)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalReopenProposed, current.ID, actor, correlationID, now, nil, after); err != nil {
			return err
		}
		payload, err := json.Marshal(signalCommandPayload{
			EventID:       uuid.New(),
			Type:          EventTypeSignalReopenProposed,
			SignalID:      current.ID,
			OccurredAt:    now,
			CorrelationID: correlationID,
			CveID:         cveID,
			From:          string(from),
			To:            string(to),
			RuleVersion:   ruleVersion,
			InputHash:     inputHash,
			Version:       current.Version,
		})
		if err != nil {
			return InfraError(op, err)
		}
		proposed = true
		return s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeSignalReopenProposed,
			Payload:     payload,
			DedupeKey:   dedupeKey,
			AvailableAt: now,
			CreatedAt:   now,
		})
	})
	if err != nil {
		return false, err
	}
	return proposed, nil
}

// publishSeedRules returns the four ch. 9.3 seed rules (P1..P4) with the
// published reason and actor stamped on every row; the repository stamps the
// snapshot version (MAX+1). The definitions are the domain seed — the single
// source of the ruleset's predicates.
func publishSeedRules(reason, actorID string) []domain.PriorityRule {
	seed := domain.SeedPriorityRules()
	out := make([]domain.PriorityRule, len(seed))
	for i, r := range seed {
		r.Reason = reason
		r.ActorID = actorID
		out[i] = r
	}
	return out
}

// ruleIDs projects the ordered rule-id list of a snapshot (audit/payload).
func ruleIDs(rules []domain.PriorityRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = string(r.RuleID)
	}
	return out
}

// priorityRulesSnapshot is the minimised `after` snapshot of a ruleset
// publish (ch. 13.5): the version, its string form and the rule ids — no
// predicate bodies, no free text.
func priorityRulesSnapshot(version int, ruleVersion string, rules []domain.PriorityRule) (json.RawMessage, error) {
	return json.Marshal(struct {
		Version     int      `json:"version"`
		RuleVersion string   `json:"rule_version"`
		RuleIDs     []string `json:"rule_ids"`
	}{Version: version, RuleVersion: ruleVersion, RuleIDs: ruleIDs(rules)})
}

// reopenProposalSnapshot is the minimised audit snapshot of a reopen proposal
// (ch. 13.5): the signal identity, its closed status, the computed priority
// before and after the recompute, and the rule version/input hash it ran
// under.
func reopenProposalSnapshot(s domain.RiskSignal, cveID string, from, to domain.Priority, ruleVersion, inputHash string) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID          string `json:"id"`
		CveID       string `json:"cve_id,omitempty"`
		Status      string `json:"status"`
		From        string `json:"from"`
		To          string `json:"to"`
		RuleVersion string `json:"rule_version"`
		InputHash   string `json:"input_hash"`
	}{
		ID:          s.ID,
		CveID:       cveID,
		Status:      string(s.Status),
		From:        string(from),
		To:          string(to),
		RuleVersion: ruleVersion,
		InputHash:   inputHash,
	})
}

// appendRulesAudit appends the audit event of a ruleset publish on the
// caller's transaction — atomic with the snapshot write (ch. 5.1, ch. 13.2).
// The audit table's aggregate_id is a uuid and a ruleset snapshot is not one
// row, so the row carries a fresh uuid and the identity of the snapshot lives
// in the `after` payload (version + rule_version + rule ids).
func (s *Service) appendRulesAudit(ctx context.Context, tx Tx, action string, actor Actor, correlationID string, now time.Time, after json.RawMessage) error {
	return s.audit.Append(ctx, tx, AuditEvent{
		AggregateType:    AuditAggregatePriorityRules,
		AggregateID:      uuid.New(),
		ActorType:        actor.Type,
		ActorID:          actor.ID,
		ActorDisplayName: actor.DisplayName,
		Action:           action,
		OccurredAt:       now,
		After:            after,
		CorrelationID:    correlationID,
	})
}

// enqueuePriorityRecompute appends one priority.recompute job on tx for the
// target signal under ruleVersion, dedupe-checked by the canonical input
// hash: an identical (signal, rule version, factor-set) job — queued, claimed
// or terminal — is a no-op (checked with ExistsDedupeKey on the same
// transaction, the exactly-once enqueuer pattern of ADR-012 point 4). It
// returns whether a row was appended.
func (s *Service) enqueuePriorityRecompute(ctx context.Context, tx Tx, target PriorityRecomputeTarget, ruleVersion, correlationID string, now time.Time) (bool, error) {
	const op = "priority_recompute.enqueue"

	inputHash, err := PriorityInputHash(ruleVersion, target.Factors)
	if err != nil {
		return false, InfraError(op, err)
	}
	dedupeKey := PriorityRecomputeDedupeKey(target.SignalID, ruleVersion, inputHash)
	exists, err := s.outbox.ExistsDedupeKey(ctx, tx, dedupeKey)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil // already enqueued under this input — exactly once
	}
	payload, err := json.Marshal(PriorityRecomputePayload{
		EventID:       uuid.New(),
		Type:          EventTypePriorityRecompute,
		SignalID:      target.SignalID,
		RuleVersion:   ruleVersion,
		InputHash:     inputHash,
		OccurredAt:    now,
		CorrelationID: correlationID,
	})
	if err != nil {
		return false, InfraError(op, err)
	}
	if err := s.outbox.Append(ctx, tx, OutboxEvent{
		Type:        EventTypePriorityRecompute,
		Payload:     payload,
		DedupeKey:   dedupeKey,
		AvailableAt: now,
		CreatedAt:   now,
	}); err != nil {
		return false, err
	}
	return true, nil
}

// enqueueOpenPriorityRecomputes is the batched fan-in of a ruleset publish
// (ARCH-004 §5): one priority.recompute job per open signal under the newly
// published ruleVersion, on the caller's transaction. It returns the number
// of rows appended (a re-publish with an already-queued input appends none).
func (s *Service) enqueueOpenPriorityRecomputes(ctx context.Context, tx Tx, ruleVersion, correlationID string, now time.Time) (int, error) {
	targets, err := s.signalTriage.OpenRecomputeTargets(ctx)
	if err != nil {
		return 0, err
	}
	enqueued := 0
	for _, target := range targets {
		appended, err := s.enqueuePriorityRecompute(ctx, tx, target, ruleVersion, correlationID, now)
		if err != nil {
			return 0, err
		}
		if appended {
			enqueued++
		}
	}
	return enqueued, nil
}

// EnqueuePriorityRecomputeForVulnerabilities is the matching.recompute fan-in
// (ARCH-004 §5): one priority.recompute job per signal whose match references
// one of the batch's vulnerability row ids, enqueued under the current
// effective priority rule version. It is the seam the matching runner drives
// after a recompute run commits its matches; the enqueues run in one
// transaction and are dedupe-checked (a signal already queued under the same
// rule version and factor-set appends nothing). It returns the number of rows
// appended. An empty batch or an unpublished ruleset is a no-op.
func (s *Service) EnqueuePriorityRecomputeForVulnerabilities(ctx context.Context, vulnerabilityIDs []string) (int, error) {
	const op = "priority_recompute.fan_in"

	if len(vulnerabilityIDs) == 0 {
		return 0, nil
	}
	version, err := s.priorityRules.EffectiveVersion(ctx)
	if err != nil {
		return 0, err
	}
	if version < 1 {
		return 0, nil // no ruleset published — nothing to evaluate
	}
	ruleVersion, err := domain.PriorityRuleVersion(version)
	if err != nil {
		return 0, InfraError(op, err)
	}
	targets, err := s.signalTriage.RecomputeTargetsByVulnerabilityIDs(ctx, vulnerabilityIDs)
	if err != nil {
		return 0, err
	}
	correlationID := correlationOrNew("")
	now := s.clock.Now()
	enqueued := 0
	err = s.runTx(ctx, func(tx Tx) error {
		for _, target := range targets {
			appended, err := s.enqueuePriorityRecompute(ctx, tx, target, ruleVersion, correlationID, now)
			if err != nil {
				return err
			}
			if appended {
				enqueued++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return enqueued, nil
}
