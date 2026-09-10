package application

import (
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// DefaultSLAReminderCadence is the ch. 9.4-shaped default reminder cadence of
// the sla.evaluate scheduler (ARCH-004 §4.4): after the first P1 escalation a
// reminder is emitted once per cadence window. It is an injected configuration
// value (ServiceDeps.SLAReminderCadence, sourced from worker config), never
// table state.
const DefaultSLAReminderCadence = time.Hour

// Service is the application service: it owns the use cases (CreateSignal,
// ListSignals, GetSignal, RunSyntheticSource, the I2 source use cases
// FetchSource / NormalizeSource / RunSource / QuarantineList / Ack /
// Reprocess, the WP-3.09b NVD full-import driver FullImportSource, the
// WP-3.05 inventory import CommitInventory and the WP-3.08 matching-run
// core RunMatching) and depends only on ports — repository
// interfaces, the clock and the transaction runner. The composition root
// (cmd/*) wires the postgres repositories and postgres.WithTx behind those
// ports (WP-1b.05 and later composition roots). The EPSS run additionally
// drives the optional epss_history feeder (WP-3.10, ServiceDeps.EpssHistory)
// on the pass transaction, after the daily-set swap.
type Service struct {
	signals    SignalRepo
	audit      AuditRepo
	outbox     OutboxRepo
	vulns      VulnerabilityRepo
	matches    MatchRepo
	runs       SourceRunRepo
	raws       RawRecordRepo
	sources    SourceRepo
	quarantine QuarantineRepo
	comps      ComponentRepo
	inventory  InventoryWriter
	epssHist   EpssHistoryAppender // optional: nil appends no epss_history (see ServiceDeps.EpssHistory)
	// I4 triage/SLA ports (WP-4.04a / DEV-075). They are optional at
	// construction — the I1b–I3 composition roots (server, worker, demo)
	// wire a Service without them and never invoke a triage command; the
	// I5b root wires all three.
	signalTriage SignalTriageRepo
	comments     CommentRepo
	slaClocks    SlaClockRepo
	// priorityRules is the versioned priority_rules snapshot port and
	// factorSource the read port of the priority factor rebuild (WP-4.04b /
	// DEV-077): PublishPriorityRules writes the next snapshot through the
	// former, RecomputePriority evaluates the effective snapshot and rebuilds
	// the factors through the latter. Like the triage/SLA ports they are
	// optional at construction — the I1b–I3 composition roots wire a Service
	// without them and never invoke these use cases; the I5b root wires all
	// five.
	priorityRules PriorityRuleRepo
	factorSource  PriorityFactorRepo
	// slaProfile is the injected (priority, target) → reaction-time duration
	// profile (ARCH-004 §4.2/§4.3). The triage commands read it to decide
	// which SLA clocks a transition fulfils or resets; it defaults to the
	// ch. 9.4 durations when ServiceDeps.SlaTimeProfile is nil.
	slaProfile domain.SLATimeProfile
	// slaReminderCadence is the injected reminder cadence of the sla.evaluate
	// scheduler (ARCH-004 §4.4): the interval between the escalation reminders
	// of an already-escalated P1. It defaults to DefaultSLAReminderCadence when
	// ServiceDeps.SLAReminderCadence is zero/negative.
	slaReminderCadence time.Duration
	clock              Clock
	runTx              TxRunner
}

// ServiceDeps are the port implementations the service runs on. RunTx is
// the transaction boundary (postgres.WithTx in production); Clock must be
// injected — production code receives the platform RealClock, tests the
// FakeClock — so no wall clock is ever read inside a use case (ch. 7.2).
type ServiceDeps struct {
	Signals         SignalRepo
	Audit           AuditRepo
	Outbox          OutboxRepo
	Vulnerabilities VulnerabilityRepo
	Matches         MatchRepo
	SourceRuns      SourceRunRepo
	RawRecords      RawRecordRepo
	Sources         SourceRepo
	Quarantine      QuarantineRepo
	Components      ComponentRepo
	Inventory       InventoryWriter
	// EpssHistory is the optional feeder of epss_history (WP-3.10/DEV-053,
	// ARCH-003 §7): the EPSS run appends the observed history of the
	// inventory-relevant CVEs on the pass transaction after the daily-set
	// swap. The dependency is additive and nil-safe — a composition root
	// whose EPSS runs need no history (or a unit test that does not exercise
	// it) leaves it nil and the run loads epss_current unchanged.
	EpssHistory EpssHistoryAppender
	// SignalTriage/Comments/SlaClocks are the I4 triage/SLA ports (WP-4.04a /
	// DEV-075). They are optional at construction so the I1b–I3 composition
	// roots (server, worker, demo) that do not drive the triage commands keep
	// wiring unchanged; a Service whose triage use cases are invoked must
	// carry them (the I5b root wires the postgres implementations).
	SignalTriage SignalTriageRepo
	Comments     CommentRepo
	SlaClocks    SlaClockRepo
	// PriorityRules/FactorSource are the I4 priority-rules and
	// priority-factor rebuild ports (WP-4.04b / DEV-077). They are optional
	// at construction so the composition roots that do not drive
	// PublishPriorityRules/RecomputePriority keep wiring unchanged; a
	// Service whose use cases are invoked must carry them (the I5b root
	// wires the postgres implementations).
	PriorityRules PriorityRuleRepo
	FactorSource  PriorityFactorRepo
	// SlaTimeProfile is the injectable (priority, target) → reaction-time
	// duration profile the I4 triage commands read to decide which SLA
	// clocks a status change fulfils or resets (ARCH-004 §4.2/§4.3,
	// FR-032/NFR-015). It is optional: a nil profile takes the ch. 9.4
	// defaults (domain.DefaultSLATimeProfile). The accelerated demo/test
	// runs inject a scaled profile without touching any status/audit logic.
	SlaTimeProfile *domain.SLATimeProfile
	// SLAReminderCadence is the reminder cadence of the sla.evaluate
	// scheduler (ARCH-004 §4.4, config not table state): the interval
	// between the escalation reminders of an already-escalated P1. It is
	// optional: zero/negative takes DefaultSLAReminderCadence. The
	// accelerated test injects a scaled cadence.
	SLAReminderCadence time.Duration
	Clock              Clock
	RunTx              TxRunner
}

// NewService assembles the service from its port implementations. A nil
// dependency is a programming error and panics at construction time rather
// than failing deep inside a use case.
func NewService(deps ServiceDeps) *Service {
	if deps.Signals == nil {
		panic("application: NewService: Signals must not be nil")
	}
	if deps.Audit == nil {
		panic("application: NewService: Audit must not be nil")
	}
	if deps.Outbox == nil {
		panic("application: NewService: Outbox must not be nil")
	}
	if deps.Vulnerabilities == nil {
		panic("application: NewService: Vulnerabilities must not be nil")
	}
	if deps.Matches == nil {
		panic("application: NewService: Matches must not be nil")
	}
	if deps.SourceRuns == nil {
		panic("application: NewService: SourceRuns must not be nil")
	}
	if deps.RawRecords == nil {
		panic("application: NewService: RawRecords must not be nil")
	}
	if deps.Sources == nil {
		panic("application: NewService: Sources must not be nil")
	}
	if deps.Quarantine == nil {
		panic("application: NewService: Quarantine must not be nil")
	}
	if deps.Components == nil {
		panic("application: NewService: Components must not be nil")
	}
	if deps.Inventory == nil {
		panic("application: NewService: Inventory must not be nil")
	}
	if deps.Clock == nil {
		panic("application: NewService: Clock must not be nil")
	}
	if deps.RunTx == nil {
		panic("application: NewService: RunTx must not be nil")
	}
	// The SLA time profile is optional: absent means the ch. 9.4 defaults
	// (ARCH-004 §4.2), so a Service keeps a defined clock vocabulary even
	// when the composition root injects no scaled profile.
	slaProfile := domain.DefaultSLATimeProfile()
	if deps.SlaTimeProfile != nil {
		slaProfile = *deps.SlaTimeProfile
	}
	// The sla.evaluate reminder cadence is optional: absent means the built-in
	// default, so a Service keeps a defined escalation cadence even without a
	// configured value (ARCH-004 §4.4).
	slaReminderCadence := deps.SLAReminderCadence
	if slaReminderCadence <= 0 {
		slaReminderCadence = DefaultSLAReminderCadence
	}
	return &Service{
		signals:            deps.Signals,
		audit:              deps.Audit,
		outbox:             deps.Outbox,
		vulns:              deps.Vulnerabilities,
		matches:            deps.Matches,
		runs:               deps.SourceRuns,
		raws:               deps.RawRecords,
		sources:            deps.Sources,
		quarantine:         deps.Quarantine,
		comps:              deps.Components,
		inventory:          deps.Inventory,
		epssHist:           deps.EpssHistory,
		signalTriage:       deps.SignalTriage,
		comments:           deps.Comments,
		slaClocks:          deps.SlaClocks,
		priorityRules:      deps.PriorityRules,
		factorSource:       deps.FactorSource,
		slaProfile:         slaProfile,
		slaReminderCadence: slaReminderCadence,
		clock:              deps.Clock,
		runTx:              deps.RunTx,
	}
}
