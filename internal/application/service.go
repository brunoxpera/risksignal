package application

// Service is the application service: it owns the use cases (CreateSignal,
// ListSignals, GetSignal, RunSyntheticSource, and the I2 source use cases
// FetchSource / NormalizeSource / RunSource / QuarantineList / Ack /
// Reprocess) and depends only on ports — repository interfaces, the clock
// and the transaction runner. The composition root (cmd/*) wires the
// postgres repositories and postgres.WithTx behind those ports (WP-1b.05
// and later composition roots).
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
	clock      Clock
	runTx      TxRunner
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
	Clock           Clock
	RunTx           TxRunner
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
	if deps.Clock == nil {
		panic("application: NewService: Clock must not be nil")
	}
	if deps.RunTx == nil {
		panic("application: NewService: RunTx must not be nil")
	}
	return &Service{
		signals:    deps.Signals,
		audit:      deps.Audit,
		outbox:     deps.Outbox,
		vulns:      deps.Vulnerabilities,
		matches:    deps.Matches,
		runs:       deps.SourceRuns,
		raws:       deps.RawRecords,
		sources:    deps.Sources,
		quarantine: deps.Quarantine,
		comps:      deps.Components,
		clock:      deps.Clock,
		runTx:      deps.RunTx,
	}
}
