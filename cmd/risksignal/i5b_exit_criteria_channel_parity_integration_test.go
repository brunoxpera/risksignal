package main

// I5b exit-criterion proof (a): cross-channel parity (ARCH-006 §6/§8a,
// NFR-013).
//
// Every one of the eight signal commands is driven through the three channels
// — the generated HTTP API (POST /api/v1/signals/{id}/commands over httptest),
// the server-rendered web form handler (an httptest server with a session-
// cookie / local-bypass principal) and the in-process CLI — against its own
// scratch database, seeded identically. The final state (status/priority/
// owner/version), the audit delta (action, actor users.id, before/after) and
// the outbox delta (type, dedupe-key shape, payload) must be identical across
// the channels: all three converge on the same application use cases, the same
// in-command authoriser and the same audit/outbox path, differing only in
// authentication transport.
//
// A forbidden role (Administrator holds no signals.triage / signals.override)
// is denied on every channel — 403 (API), a re-rendered denial (web, 403) and
// exit 4 (CLI) — with no audit row written on any channel. The same
// cross-channel assertion runs for the staged inventory import (API
// POST→GET→commit vs CLI `inventory import --commit`) and for user role
// grant/revoke (API PATCH /users/{id}/roles vs CLI `user grant|revoke`).
//
// The comparison masks only the values a run cannot share: the channel-local
// signal/import/comment/event identifiers and the clock-derived timestamps
// (the CLI drives the real clock; the API/web channels drive an injected,
// monotonically advancing fake clock so the audit/outbox order is
// deterministic). Everything else — action, actor, status, priority, owner,
// version, counts, reasons, targets — is compared verbatim. The tests skip
// when no PostgreSQL is reachable (newTestDB), like every other integration
// test.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	apigen "github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	pggen "github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/web"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	webassets "github.com/brunoxpera/risksignal/web"
)

// Fixed seeded identities (migration 00009) the parity runs act as; the
// single-role users carry exactly one role, so the permission matrix is
// exercised without the multi-role local-developer shortcut.
const (
	i5bAnalystSubject = "local::security-analyst"
	i5bAdminSubject   = "local::administrator"
	i5bAdminUserID    = "e5a00000-0000-4000-8000-000000000004"
)

// i5bClock is the injected clock of the parity channels: a fixed base instant
// that advances by step on every read, so each command of a channel is stamped
// strictly later than the previous one and the audit/outbox order is
// deterministic across the independently seeded channel databases.
type i5bClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func newI5bClock(base time.Time) *i5bClock {
	return &i5bClock{now: base, step: time.Second}
}

func (c *i5bClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now
	c.now = c.now.Add(c.step)
	return now
}

// i5bTestLogger is a discard logger for the stacks.
func i5bTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newI5bService wires the application service over the postgres repositories
// exactly as the I5b server root does (assets/import/admin/triage ports), with
// the injected clock and the given outbox repository behind the ARCH-001 §5
// seam.
func newI5bService(pool *pgxpool.Pool, clk clock.Clock, outbox application.OutboxRepo) *application.Service {
	q := pggen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:          repo.NewSignalRepo(q),
		Audit:            repo.NewAuditRepo(q),
		Outbox:           outbox,
		Vulnerabilities:  repo.NewVulnerabilityRepo(q),
		Matches:          repo.NewMatchRepo(q),
		SourceRuns:       repo.NewSourceRunRepo(q),
		RawRecords:       repo.NewRawRecordRepo(q),
		Sources:          repo.NewSourceRepo(q),
		Quarantine:       repo.NewQuarantineRepo(q),
		Components:       repo.NewComponentRepo(q),
		Inventory:        repo.NewInventoryRepo(q),
		Users:            repo.NewUserRepo(q),
		Assets:           repo.NewAssetRepo(q),
		InventoryReader:  repo.NewInventoryRepo(q),
		InventoryImports: repo.NewInventoryImportRepo(q),
		UserAdmin:        repo.NewUserRepo(q),
		SignalTriage:     repo.NewSignalRepo(q),
		Comments:         repo.NewCommentRepo(q),
		SlaClocks:        repo.NewSlaClockRepo(q),
		PriorityRules:    repo.NewPriorityRuleRepo(q),
		FactorSource:     repo.NewPriorityFactorRepo(q),
		Clock:            clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// i5bFixture is one migrated scratch database seeded with a single P1/new
// signal through the real CreateSignal command. Each parity comparison owns one
// fixture per channel so the runs start from an identical, independent
// baseline.
type i5bFixture struct {
	pool   *pgxpool.Pool
	dbURL  string
	signal domain.RiskSignal
	base   time.Time
}

func newI5bFixture(t *testing.T) *i5bFixture {
	t.Helper()
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	if code, _, stderr := runCLI(t, env, "maintenance", "migrate"); code != exitOK {
		t.Fatalf("migrate exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	matchID := seedCreateSignalFixture(t, pool, base)
	svc := newI5bService(pool, clock.NewFakeClock(base), repo.NewOutboxRepo(pggen.New(pool)))
	created, err := svc.CreateSignal(ctx, faultTestInput(matchID))
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	return &i5bFixture{pool: pool, dbURL: dbURL, signal: created.Signal, base: base}
}

// i5bStep is one command of the parity sequence: the wire command name plus the
// fields that command uses.
type i5bStep struct {
	name     string
	command  string
	status   string
	reason   string
	ownerID  string
	comment  string
	priority string
	target   string
}

// i5bSequence is the ordered command set driven through every channel. It
// exercises all eight commands on one P1/new fixture, threading the
// optimistic-lock version from command to command (re-read from each channel's
// database). Order: acknowledge, assign, comment, pause, resume, override,
// revert, transition — pause/resume before the transition so the decision clock
// still exists.
func i5bSequence() []i5bStep {
	return []i5bStep{
		{name: "acknowledge", command: "acknowledge"},
		{name: "assign_owner", command: "assign_owner", ownerID: i5bAnalystUserID},
		{name: "add_comment", command: "add_comment", comment: "initial triage note"},
		{name: "pause_sla", command: "pause_sla", target: "decision", reason: "vendor outage"},
		{name: "resume_sla", command: "resume_sla", target: "decision", reason: "vendor restored"},
		{name: "override_priority", command: "override_priority", priority: "P3", reason: "compensating control"},
		{name: "revert_priority", command: "revert_priority"},
		{name: "change_status", command: "change_status", status: "action_planned"},
	}
}

// i5bChannel is one driving surface of the parity comparison.
type i5bChannel interface {
	name() string
	pool() *pgxpool.Pool
	signalID() string
	// command drives one command; expectAllowed selects success vs a denial
	// assertion.
	command(t *testing.T, step i5bStep, expectedVersion int, expectAllowed bool)
}

// i5bState is the observable signal state parity compares.
type i5bState struct {
	Status   string
	Priority string
	Owner    string
	Version  int
}

func i5bReadState(t *testing.T, ch i5bChannel) i5bState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var s i5bState
	if err := ch.pool().QueryRow(ctx,
		`SELECT status, priority, coalesce(owner, ''), version FROM risk_signals WHERE id = $1`, ch.signalID()).
		Scan(&s.Status, &s.Priority, &s.Owner, &s.Version); err != nil {
		t.Fatalf("%s: read signal state: %v", ch.name(), err)
	}
	return s
}

// --- API channel -----------------------------------------------------------

type i5bAPIChannel struct {
	fixture *i5bFixture
	client  *apigen.ClientWithResponses
}

func newI5bAPIChannel(t *testing.T, f *i5bFixture, principal string) *i5bAPIChannel {
	t.Helper()
	svc := newI5bService(f.pool, newI5bClock(f.base.Add(time.Second)), repo.NewOutboxRepo(pggen.New(f.pool)))
	srv := newI5bAPIStack(t, svc, principal)
	client, err := apigen.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("gen.NewClientWithResponses: %v", err)
	}
	return &i5bAPIChannel{fixture: f, client: client}
}

func (c *i5bAPIChannel) name() string        { return "api" }
func (c *i5bAPIChannel) pool() *pgxpool.Pool { return c.fixture.pool }
func (c *i5bAPIChannel) signalID() string    { return c.fixture.signal.ID }

func (c *i5bAPIChannel) command(t *testing.T, step i5bStep, expectedVersion int, expectAllowed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.client.SignalCommandWithResponse(ctx, c.signalID(), i5bGenRequest(step, expectedVersion))
	if err != nil {
		t.Fatalf("API %s: %v", step.name, err)
	}
	if expectAllowed {
		if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
			t.Fatalf("API %s status = %d (body %s), want 200", step.name, resp.StatusCode(), resp.Body)
		}
		return
	}
	if resp.StatusCode() != http.StatusForbidden {
		t.Fatalf("API %s (forbidden) status = %d (body %s), want 403", step.name, resp.StatusCode(), resp.Body)
	}
}

// i5bGenRequest maps one step onto the generated request shape.
func i5bGenRequest(step i5bStep, expectedVersion int) apigen.SignalCommandRequest {
	req := apigen.SignalCommandRequest{Command: apigen.SignalCommandRequestCommand(step.command)}
	version := func() *int { v := expectedVersion; return &v }
	switch step.command {
	case "acknowledge":
		req.ExpectedVersion = version()
	case "change_status":
		s := apigen.SignalStatus(step.status)
		req.Status = &s
		req.ExpectedVersion = version()
		if step.reason != "" {
			r := step.reason
			req.Reason = &r
		}
	case "assign_owner":
		o := step.ownerID
		req.OwnerId = &o
		req.ExpectedVersion = version()
	case "add_comment":
		cm := step.comment
		req.Comment = &cm
	case "override_priority":
		p := apigen.Priority(step.priority)
		r := step.reason
		req.Priority = &p
		req.Reason = &r
		req.ExpectedVersion = version()
	case "revert_priority":
		req.ExpectedVersion = version()
	case "pause_sla", "resume_sla":
		tg := apigen.SLATarget(step.target)
		r := step.reason
		req.Target = &tg
		req.Reason = &r
	}
	return req
}

// --- Web channel -----------------------------------------------------------

type i5bWebChannel struct {
	fixture *i5bFixture
	srv     *httptest.Server
	client  *http.Client
}

func newI5bWebChannel(t *testing.T, f *i5bFixture, principal string) *i5bWebChannel {
	t.Helper()
	svc := newI5bService(f.pool, newI5bClock(f.base.Add(time.Second)), repo.NewOutboxRepo(pggen.New(f.pool)))
	srv := newI5bWebStack(t, svc, f.pool, clock.NewFakeClock(f.base), principal)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &i5bWebChannel{fixture: f, srv: srv, client: &http.Client{Jar: jar}}
}

func (c *i5bWebChannel) name() string        { return "web" }
func (c *i5bWebChannel) pool() *pgxpool.Pool { return c.fixture.pool }
func (c *i5bWebChannel) signalID() string    { return c.fixture.signal.ID }

// confirmToken extracts the confirmation token of the form whose action is
// actionURL (the destructive-action server-side gate, ARCH-006 §4 row 3).
func (c *i5bWebChannel) confirmToken(t *testing.T, page, actionURL string) string {
	t.Helper()
	idx := strings.Index(page, `action="`+actionURL+`"`)
	if idx < 0 {
		t.Fatalf("web: form %q not found on the page", actionURL)
	}
	return i5bHiddenField(t, page[idx:], "confirm_token")
}

func (c *i5bWebChannel) command(t *testing.T, step i5bStep, expectedVersion int, expectAllowed bool) {
	t.Helper()
	page := i5bWebGet(t, c.client, c.srv.URL+"/signals/"+c.signalID())
	route, form := i5bWebForm(step, expectedVersion)
	form["csrf_token"] = i5bHiddenField(t, page, "csrf_token")
	if i5bNeedsConfirm(route) {
		form["confirm_token"] = c.confirmToken(t, page, "/signals/"+c.signalID()+route)
	}
	resp := i5bWebPost(t, c.client, c.srv.URL+"/signals/"+c.signalID()+route, form)
	defer func() { _ = resp.Body.Close() }()
	if expectAllowed {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("web %s status = %d, want 200", step.name, resp.StatusCode)
		}
		return
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("web %s (forbidden) status = %d, want 403", step.name, resp.StatusCode)
	}
}

// i5bNeedsConfirm lists the web routes whose form carries a confirmation token
// (ARCH-006 §4 row 3).
func i5bNeedsConfirm(route string) bool {
	switch route {
	case "/transition", "/override", "/revert", "/pause-sla":
		return true
	}
	return false
}

// i5bWebForm maps a step onto the web adapter's route + form fields.
func i5bWebForm(step i5bStep, expectedVersion int) (string, map[string]string) {
	form := map[string]string{}
	version := strconv.Itoa(expectedVersion)
	switch step.command {
	case "acknowledge":
		form["expected_version"] = version
		return "/acknowledge", form
	case "change_status":
		form["status"] = step.status
		form["reason"] = step.reason
		form["expected_version"] = version
		return "/transition", form
	case "assign_owner":
		form["owner_id"] = step.ownerID
		form["expected_version"] = version
		return "/assign", form
	case "add_comment":
		form["comment"] = step.comment
		return "/comment", form
	case "override_priority":
		form["priority"] = step.priority
		form["reason"] = step.reason
		form["expected_version"] = version
		return "/override", form
	case "revert_priority":
		form["expected_version"] = version
		return "/revert", form
	case "pause_sla":
		form["target"] = step.target
		form["reason"] = step.reason
		return "/pause-sla", form
	case "resume_sla":
		form["target"] = step.target
		form["reason"] = step.reason
		return "/resume-sla", form
	}
	panic("i5bWebForm: unknown command " + step.command)
}

// --- CLI channel -----------------------------------------------------------

type i5bCLIChannel struct {
	fixture *i5bFixture
	env     map[string]string
	as      string
}

func newI5bCLIChannel(t *testing.T, f *i5bFixture, as string) *i5bCLIChannel {
	t.Helper()
	return &i5bCLIChannel{fixture: f, env: cliDBEnv(f.dbURL), as: as}
}

func (c *i5bCLIChannel) name() string        { return "cli" }
func (c *i5bCLIChannel) pool() *pgxpool.Pool { return c.fixture.pool }
func (c *i5bCLIChannel) signalID() string    { return c.fixture.signal.ID }

func (c *i5bCLIChannel) command(t *testing.T, step i5bStep, expectedVersion int, expectAllowed bool) {
	t.Helper()
	args := append(i5bCLIArgs(c.signalID(), c.as, step, expectedVersion), "--output", "json")
	code, stdout, stderr := runCLI(t, c.env, args...)
	if expectAllowed {
		if code != exitOK {
			t.Fatalf("CLI %s exit = %d, want 0 (stdout: %s, stderr: %s)", step.name, code, stdout, stderr)
		}
		return
	}
	if code != exitAuthorisation {
		t.Fatalf("CLI %s (forbidden) exit = %d, want %d (stdout: %s, stderr: %s)", step.name, code, exitAuthorisation, stdout, stderr)
	}
}

// i5bCLIArgs maps a step onto the CLI argv (1:1 with the wire vocabulary).
func i5bCLIArgs(signalID, as string, step i5bStep, expectedVersion int) []string {
	v := strconv.Itoa(expectedVersion)
	switch step.command {
	case "acknowledge":
		return []string{"signal", "acknowledge", "--signal", signalID, "--version", v, "--as", as}
	case "change_status":
		return []string{"signal", "transition", "--signal", signalID, "--to", step.status, "--reason", step.reason, "--version", v, "--as", as}
	case "assign_owner":
		return []string{"signal", "assign", "--signal", signalID, "--owner", step.ownerID, "--version", v, "--as", as}
	case "add_comment":
		return []string{"signal", "comment", "--signal", signalID, "--comment", step.comment, "--as", as}
	case "override_priority":
		return []string{"signal", "override", "--signal", signalID, "--priority", step.priority, "--reason", step.reason, "--version", v, "--as", as}
	case "revert_priority":
		return []string{"signal", "revert", "--signal", signalID, "--version", v, "--as", as}
	case "pause_sla":
		return []string{"signal", "pause", "--signal", signalID, "--target", step.target, "--reason", step.reason, "--as", as}
	case "resume_sla":
		return []string{"signal", "resume", "--signal", signalID, "--target", step.target, "--reason", step.reason, "--as", as}
	}
	panic("i5bCLIArgs: unknown command " + step.command)
}

// --- the parity proofs -----------------------------------------------------

// TestI5bExitCriteriaChannelParitySignalCommands is the ARCH-006 §8a proof for
// the eight signal commands.
func TestI5bExitCriteriaChannelParitySignalCommands(t *testing.T) {
	apiCh := newI5bAPIChannel(t, newI5bFixture(t), "security-analyst")
	webCh := newI5bWebChannel(t, newI5bFixture(t), "security-analyst")
	cliCh := newI5bCLIChannel(t, newI5bFixture(t), i5bAnalystSubject)
	channels := []i5bChannel{apiCh, webCh, cliCh}

	// --- allowed sequence, in lockstep -------------------------------------
	for _, step := range i5bSequence() {
		for _, ch := range channels {
			ch.command(t, step, i5bReadState(t, ch).Version, true)
		}
		want := i5bReadState(t, channels[0])
		for _, ch := range channels[1:] {
			if got := i5bReadState(t, ch); got != want {
				t.Fatalf("state parity diverged after %q: %s %+v vs %s %+v", step.name, ch.name(), got, channels[0].name(), want)
			}
		}
	}

	// The final state: acknowledged → in_review, owner assigned, priority
	// overridden then reverted to the computed P1, transitioned to
	// action_planned; version 1 + five version-guarded commands.
	wantFinal := i5bState{Status: "action_planned", Priority: "P1", Owner: i5bAnalystUserID, Version: 6}
	for _, ch := range channels {
		if got := i5bReadState(t, ch); got != wantFinal {
			t.Fatalf("%s final state = %+v, want %+v", ch.name(), got, wantFinal)
		}
	}

	// --- audit + outbox parity ---------------------------------------------
	refAudits := i5bAuditDelta(t, channels[0])
	if len(refAudits) != len(i5bSequence()) {
		t.Fatalf("audit delta = %d rows, want %d (one per command)", len(refAudits), len(i5bSequence()))
	}
	refOutbox := i5bOutboxDelta(t, channels[0])
	if len(refOutbox) != len(i5bSequence()) {
		t.Fatalf("outbox delta = %d rows, want %d (one per command)", len(refOutbox), len(i5bSequence()))
	}
	for _, ch := range channels[1:] {
		if got := i5bAuditDelta(t, ch); !reflect.DeepEqual(got, refAudits) {
			t.Fatalf("%s audit delta diverged from %s:\n got %s\nwant %s", ch.name(), channels[0].name(), i5bFmt(got), i5bFmt(refAudits))
		}
		if got := i5bOutboxDelta(t, ch); !reflect.DeepEqual(got, refOutbox) {
			t.Fatalf("%s outbox delta diverged from %s:\n got %s\nwant %s", ch.name(), channels[0].name(), i5bFmt(got), i5bFmt(refOutbox))
		}
	}

	// Every command is audited as the acting user principal (users.id).
	for _, row := range refAudits {
		if row.ActorType != application.ActorTypeUser || row.ActorID != parityAnalystUser {
			t.Fatalf("audit actor = %s/%s, want user/%s", row.ActorType, row.ActorID, parityAnalystUser)
		}
	}

	// --- forbidden role on every channel -----------------------------------
	adminChannels := []i5bChannel{
		newI5bAPIChannel(t, apiCh.fixture, "administrator"),
		newI5bWebChannel(t, webCh.fixture, "administrator"),
		newI5bCLIChannel(t, cliCh.fixture, i5bAdminSubject),
	}
	for _, ch := range adminChannels {
		beforeAudits := countSignalAudits(t, context.Background(), ch.pool(), ch.signalID())
		beforeState := i5bReadState(t, ch)
		for _, step := range i5bSequence() {
			ch.command(t, step, i5bReadState(t, ch).Version, false)
		}
		if got := countSignalAudits(t, context.Background(), ch.pool(), ch.signalID()); got != beforeAudits {
			t.Fatalf("%s: a denied command wrote an audit row (%d -> %d)", ch.name(), beforeAudits, got)
		}
		if got := i5bReadState(t, ch); got != beforeState {
			t.Fatalf("%s: a denied command changed the state (%+v -> %+v)", ch.name(), beforeState, got)
		}
	}
}

// TestI5bExitCriteriaChannelParityInventoryImport is the ARCH-006 §8a proof for
// the staged inventory import: API POST→GET→commit vs CLI `import --commit`.
// The stored inventory (assets/components) and the single matching.rebuild job
// must be identical; the audit action, the acting user (`users.id`) and the
// minimised after snapshot match across the channels (NFR-013): the CLI
// resolves the same administrator principal from --as that the API derives
// from its authenticated bypass identity.
func TestI5bExitCriteriaChannelParityInventoryImport(t *testing.T) {
	apiF := newI5bFixture(t)
	cliF := newI5bFixture(t)

	rows := []string{
		inventoryITVendorRow("parity-a1", "Portal-Host", "acme", "portal", "2.4.4"),
		inventoryITVendorRow("parity-a2", "Edge-Host", "acme", "edge", "1.0.0"),
	}
	csvBytes := []byte(inventoryITHeader + "\n" + strings.Join(rows, "\n") + "\n")

	// --- API channel: staged upload → get → commit -------------------------
	svc := newI5bService(apiF.pool, newI5bClock(apiF.base.Add(time.Second)), repo.NewOutboxRepo(pggen.New(apiF.pool)))
	client, err := apigen.NewClientWithResponses(newI5bAPIStack(t, svc, "administrator").URL)
	if err != nil {
		t.Fatalf("api client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	upload, err := client.CreateInventoryImportWithBodyWithResponse(ctx, "text/csv", strings.NewReader(string(csvBytes)))
	if err != nil {
		t.Fatalf("API upload: %v", err)
	}
	if upload.StatusCode() != http.StatusOK || upload.JSON200 == nil {
		t.Fatalf("API upload status = %d (body %s), want 200", upload.StatusCode(), upload.Body)
	}
	importID := upload.JSON200.Id
	if got, err := client.GetInventoryImportWithResponse(ctx, importID); err != nil || got.StatusCode() != http.StatusOK {
		t.Fatalf("API get import = %v (err %v), want 200", got, err)
	}
	commit, err := client.CommitInventoryImportWithResponse(ctx, importID)
	if err != nil {
		t.Fatalf("API commit: %v", err)
	}
	if commit.StatusCode() != http.StatusOK || commit.JSON200 == nil || commit.JSON200.Status != apigen.Committed {
		t.Fatalf("API commit status = %d (body %s), want 200 committed", commit.StatusCode(), commit.Body)
	}

	// --- CLI channel: import --commit --------------------------------------
	file := writeInventoryITFile(t, rows...)
	code, stdout, stderr := runCLI(t, cliDBEnv(cliF.dbURL), "inventory", "import", file, "--commit", "--as", i5bAdminSubject, "--output", "json")
	if code != exitOK {
		t.Fatalf("CLI import --commit exit = %d, want 0 (stdout: %s, stderr: %s)", code, stdout, stderr)
	}

	// --- inventory + job parity --------------------------------------------
	wantAssets := i5bAssetsSnapshot(t, apiF.pool)
	if len(wantAssets) != 3 { // the signal fixture asset + the two imported assets
		t.Fatalf("API assets = %v, want the fixture asset and two imported", wantAssets)
	}
	if got := i5bAssetsSnapshot(t, cliF.pool); !reflect.DeepEqual(got, wantAssets) {
		t.Fatalf("inventory/import assets diverged:\n api %v\n cli %v", wantAssets, got)
	}
	wantComp := i5bComponentsSnapshot(t, apiF.pool)
	if got := i5bComponentsSnapshot(t, cliF.pool); !reflect.DeepEqual(got, wantComp) {
		t.Fatalf("inventory/import components diverged:\n api %v\n cli %v", wantComp, got)
	}
	wantJob := i5bRebuildJobs(t, apiF.pool)
	if len(wantJob) != 1 {
		t.Fatalf("API matching.rebuild jobs = %v, want exactly one", wantJob)
	}
	wantJob[0].Snapshot = "" // the snapshot hash is clock-derived; compare the rest
	gotJob := i5bRebuildJobs(t, cliF.pool)
	if len(gotJob) != 1 {
		t.Fatalf("CLI matching.rebuild jobs = %v, want exactly one", gotJob)
	}
	gotJob[0].Snapshot = ""
	if !reflect.DeepEqual(gotJob[0], wantJob[0]) {
		t.Fatalf("matching.rebuild job diverged:\n api %v\n cli %v", wantJob, gotJob)
	}

	// --- audit parity (action + minimised after) ---------------------------
	wantAudit := i5bInventoryAudit(t, apiF.pool)
	if len(wantAudit) != 1 || wantAudit[0].Action != application.AuditActionInventoryImport {
		t.Fatalf("API inventory audit = %v, want one %s row", wantAudit, application.AuditActionInventoryImport)
	}
	gotAudit := i5bInventoryAudit(t, cliF.pool)
	if len(gotAudit) != 1 || gotAudit[0].Action != wantAudit[0].Action || gotAudit[0].After != wantAudit[0].After {
		t.Fatalf("inventory audit diverged:\n api %v\n cli %v", wantAudit, gotAudit)
	}
	// The acting principal is the same on both channels (NFR-013): the API
	// commit stamps its resolved bypass user, the CLI commit the user its
	// --as subject resolves to — here the same Administrator identity.
	if wantAudit[0].ActorType != application.ActorTypeUser || wantAudit[0].ActorID != i5bAdminUserID {
		t.Fatalf("API inventory audit actor = %s/%s, want user/%s", wantAudit[0].ActorType, wantAudit[0].ActorID, i5bAdminUserID)
	}
	if gotAudit[0].ActorType != application.ActorTypeUser || gotAudit[0].ActorID != i5bAdminUserID {
		t.Fatalf("CLI inventory audit actor = %s/%s, want user/%s (the --as principal)", gotAudit[0].ActorType, gotAudit[0].ActorID, i5bAdminUserID)
	}
	if gotAudit[0].ActorType != wantAudit[0].ActorType || gotAudit[0].ActorID != wantAudit[0].ActorID {
		t.Fatalf("inventory audit actor diverged:\n api %s/%s\n cli %s/%s", wantAudit[0].ActorType, wantAudit[0].ActorID, gotAudit[0].ActorType, gotAudit[0].ActorID)
	}
}

// TestI5bExitCriteriaChannelParityUserRoles is the ARCH-006 §8a proof for the
// user role grant/revoke: API PATCH /users/{id}/roles vs CLI `user grant|revoke`.
func TestI5bExitCriteriaChannelParityUserRoles(t *testing.T) {
	apiF := newI5bFixture(t)
	cliF := newI5bFixture(t)

	// API: grant then revoke product_owner on the auditor.
	svc := newI5bService(apiF.pool, newI5bClock(apiF.base.Add(time.Second)), repo.NewOutboxRepo(pggen.New(apiF.pool)))
	client, err := apigen.NewClientWithResponses(newI5bAPIStack(t, svc, "administrator").URL)
	if err != nil {
		t.Fatalf("api client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	grant, err := client.UpdateUserRolesWithResponse(ctx, i5bAuditorUserID, apigen.UpdateUserRolesJSONRequestBody{
		Grant: []apigen.Role{apigen.ProductOwner}, Revoke: []apigen.Role{},
	})
	if err != nil || grant.StatusCode() != http.StatusOK {
		t.Fatalf("API grant = %v (err %v), want 200", grant, err)
	}
	revoke, err := client.UpdateUserRolesWithResponse(ctx, i5bAuditorUserID, apigen.UpdateUserRolesJSONRequestBody{
		Grant: []apigen.Role{}, Revoke: []apigen.Role{apigen.ProductOwner},
	})
	if err != nil || revoke.StatusCode() != http.StatusOK {
		t.Fatalf("API revoke = %v (err %v), want 200", revoke, err)
	}

	// CLI: the same grant then revoke.
	env := cliDBEnv(cliF.dbURL)
	if code, _, stderr := runCLI(t, env, "user", "grant", "--user", i5bAuditorUserID, "--role", "product_owner", "--as", i5bAdminSubject, "--output", "json"); code != exitOK {
		t.Fatalf("CLI grant exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if code, _, stderr := runCLI(t, env, "user", "revoke", "--user", i5bAuditorUserID, "--role", "product_owner", "--as", i5bAdminSubject, "--output", "json"); code != exitOK {
		t.Fatalf("CLI revoke exit = %d, want 0 (stderr: %s)", code, stderr)
	}

	// user_roles parity: the auditor holds the same roles after the round-trip.
	wantRoles := i5bRolesOf(t, apiF.pool, i5bAuditorUserID)
	if !reflect.DeepEqual(wantRoles, []string{"auditor"}) {
		t.Fatalf("API roles of auditor = %v, want [auditor] after grant+revoke", wantRoles)
	}
	if got := i5bRolesOf(t, cliF.pool, i5bAuditorUserID); !reflect.DeepEqual(got, wantRoles) {
		t.Fatalf("user_roles diverged: api %v, cli %v", wantRoles, got)
	}

	// audit parity: identical role_granted/role_revoked rows (action, actor,
	// after) — the actor is the acting Administrator on both channels.
	wantAudit := i5bUserAudit(t, apiF.pool, i5bAuditorUserID)
	if len(wantAudit) != 2 || wantAudit[0].Action != application.AuditActionUserRoleGranted || wantAudit[1].Action != application.AuditActionUserRoleRevoked {
		t.Fatalf("API user audit = %v, want granted then revoked", wantAudit)
	}
	if got := i5bUserAudit(t, cliF.pool, i5bAuditorUserID); !reflect.DeepEqual(got, wantAudit) {
		t.Fatalf("user audit diverged:\n api %v\n cli %v", wantAudit, got)
	}
	for _, row := range wantAudit {
		if row.ActorType != application.ActorTypeUser || row.ActorID != i5bAdminUserID {
			t.Fatalf("user audit actor = %s/%s, want user/%s", row.ActorType, row.ActorID, i5bAdminUserID)
		}
	}
}

// --- comparison helpers ----------------------------------------------------

// i5bAudit is one normalised audit row of a channel's delta.
type i5bAudit struct {
	Action    string
	ActorType string
	ActorID   string
	Before    string
	After     string
}

// i5bAuditDelta reads the signal's audit delta — every row except the creation
// baseline — normalised against the channel-local signal id. The baseline is
// selected by action (not position) so the comparison is independent of the
// host clock ordering relative to the injected fixture clock.
func i5bAuditDelta(t *testing.T, ch i5bChannel) []i5bAudit {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := ch.pool().Query(ctx,
		`SELECT action, actor_type, actor_id, before, after FROM audit_events WHERE aggregate_id = $1 ORDER BY occurred_at, id`,
		ch.signalID())
	if err != nil {
		t.Fatalf("%s: read audits: %v", ch.name(), err)
	}
	defer rows.Close()
	var delta []i5bAudit
	for rows.Next() {
		var r i5bAudit
		var before, after []byte
		if err := rows.Scan(&r.Action, &r.ActorType, &r.ActorID, &before, &after); err != nil {
			t.Fatalf("%s: scan audit: %v", ch.name(), err)
		}
		if r.Action == application.EventTypeSignalCreated {
			continue // the creation baseline
		}
		r.Before = i5bMaskJSON(t, before)
		r.After = i5bMaskJSON(t, after)
		delta = append(delta, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: read audits: %v", ch.name(), err)
	}
	return delta
}

// i5bOutboxRow is one normalised outbox row of a channel's delta.
type i5bOutboxRow struct {
	Type    string
	Dedupe  string
	Payload string
}

// i5bOutboxDelta reads the signal's outbox delta — every row except the
// creation baseline — normalising the channel-local ids and the dedupe-key
// shape.
func i5bOutboxDelta(t *testing.T, ch i5bChannel) []i5bOutboxRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := ch.pool().Query(ctx, `SELECT type, dedupe_key, payload FROM outbox ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("%s: read outbox: %v", ch.name(), err)
	}
	defer rows.Close()
	var delta []i5bOutboxRow
	for rows.Next() {
		var r i5bOutboxRow
		var dedupe string
		var payload []byte
		if err := rows.Scan(&r.Type, &dedupe, &payload); err != nil {
			t.Fatalf("%s: scan outbox: %v", ch.name(), err)
		}
		if r.Type == application.EventTypeSignalCreated {
			continue // the creation baseline
		}
		r.Dedupe = i5bDedupeShape(t, dedupe, ch.signalID())
		r.Payload = i5bMaskJSON(t, payload)
		delta = append(delta, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: read outbox: %v", ch.name(), err)
	}
	return delta
}

// i5bDedupeShape verifies the <type>:<signal_id>:<event_id> key and renders the
// channel-independent shape.
func i5bDedupeShape(t *testing.T, key, signalID string) string {
	t.Helper()
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 || parts[1] != signalID {
		t.Fatalf("outbox dedupe_key = %q, want <type>:%s:<event>", key, signalID)
	}
	return parts[0] + ":<signal>:<event>"
}

// i5bMaskJSON decodes a JSON snapshot/payload and masks the values a run cannot
// share: the channel-local ids, the clock-derived timestamps and the
// clock-delta pause seconds. Map keys are marshalled in sorted order, so the
// rendering is deterministic.
func i5bMaskJSON(t *testing.T, raw []byte) string {
	t.Helper()
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode snapshot %q: %v", raw, err)
	}
	for k := range m {
		switch {
		case k == "id" || k == "signal_id" || k == "comment_id":
			m[k] = "<id>"
		case strings.HasSuffix(k, "_id"):
			m[k] = "<id>" // correlation/event/import/asset/component ids
		case strings.HasSuffix(k, "_at"):
			m[k] = "<ts>"
		case k == "paused_seconds":
			m[k] = "<n>"
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal masked snapshot: %v", err)
	}
	return string(out)
}

// i5bFmt renders a comparison value for a failure message.
func i5bFmt(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// --- stack builders --------------------------------------------------------

// newI5bAPIStack builds the real API route table (commands + the I5b
// operations) behind the I5a authentication middleware (local bypass).
func newI5bAPIStack(t *testing.T, svc *application.Service, principal string) *httptest.Server {
	t.Helper()
	logger := i5bTestLogger()
	mux := http.NewServeMux()
	gate := httpapi.NewPermissionGate(nil, logger)
	httpapi.RegisterAPIRoutes(gate.Decorate(mux), httpapi.NewAPIHandler(svc, svc, svc, logger,
		httpapi.I5BAPI{Inventory: svc, Assets: svc, Users: svc}))
	auth := httpapi.AuthenticationMiddleware(nil, nil, httpapi.AuthOptions{BypassEnabled: true, BypassPrincipal: principal})
	srv := httptest.NewServer(auth(mux))
	t.Cleanup(srv.Close)
	return srv
}

// newI5bWebStack builds the server-rendered web adapter over the real service,
// behind the same authentication middleware (the local-bypass principal stands
// in for the session cookie).
func newI5bWebStack(t *testing.T, svc *application.Service, pool *pgxpool.Pool, renderClock clock.Clock, principal string) *httptest.Server {
	t.Helper()
	logger := i5bTestLogger()
	mux := http.NewServeMux()
	gate := httpapi.NewPermissionGate(nil, logger)
	webUI, err := web.New(web.Options{
		Service:   svc,
		Roles:     repo.NewUserRepo(pggen.New(pool)),
		Logger:    logger,
		Clock:     renderClock,
		Identity:  httpapi.IdentityFromContext,
		Templates: webassets.Templates,
		Assets:    webassets.Assets,
	})
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	webUI.Register(mux, gate)
	auth := httpapi.AuthenticationMiddleware(nil, nil, httpapi.AuthOptions{BypassEnabled: true, BypassPrincipal: principal})
	srv := httptest.NewServer(auth(mux))
	t.Cleanup(srv.Close)
	return srv
}

// --- HTTP helpers ----------------------------------------------------------

// i5bHiddenField extracts the value of the first hidden input named name from
// the HTML fragment.
func i5bHiddenField(t *testing.T, html, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("hidden field %q not found", name)
	}
	return m[1]
}

// i5bWebGet performs an authenticated GET and returns the body.
func i5bWebGet(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read GET %s: %v", target, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", target, resp.StatusCode)
	}
	return string(body)
}

// i5bWebPost performs an authenticated form POST.
func i5bWebPost(t *testing.T, client *http.Client, target string, form map[string]string) *http.Response {
	t.Helper()
	values := url.Values{}
	for k, v := range form {
		values.Set(k, v)
	}
	resp, err := client.PostForm(target, values)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

// --- database snapshot helpers ---------------------------------------------

func i5bAssetsSnapshot(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		`SELECT source, external_id, type, name, environment, criticality, exposure FROM assets ORDER BY source, external_id`)
	if err != nil {
		t.Fatalf("read assets: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var source, externalID, typ, name, env, crit, exp string
		if err := rows.Scan(&source, &externalID, &typ, &name, &env, &crit, &exp); err != nil {
			t.Fatalf("scan asset: %v", err)
		}
		out = append(out, strings.Join([]string{source, externalID, typ, name, env, crit, exp}, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read assets: %v", err)
	}
	sort.Strings(out)
	return out
}

func i5bComponentsSnapshot(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		`SELECT a.source, a.external_id, c.vendor, c.product, c.version, c.natural_key
		 FROM components c JOIN assets a ON a.id = c.asset_id
		 ORDER BY a.source, a.external_id, c.vendor, c.product, c.version`)
	if err != nil {
		t.Fatalf("read components: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var source, externalID, vendor, product, version, naturalKey string
		if err := rows.Scan(&source, &externalID, &vendor, &product, &version, &naturalKey); err != nil {
			t.Fatalf("scan component: %v", err)
		}
		out = append(out, strings.Join([]string{source, externalID, vendor, product, version, naturalKey}, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read components: %v", err)
	}
	sort.Strings(out)
	return out
}

// i5bJob is one matching.rebuild job's comparable description.
type i5bJob struct {
	Type        string
	RuleVersion string
	Snapshot    string
}

func i5bRebuildJobs(t *testing.T, pool *pgxpool.Pool) []i5bJob {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `SELECT payload FROM outbox WHERE type = $1`, application.EventTypeMatchingRebuild)
	if err != nil {
		t.Fatalf("read matching.rebuild jobs: %v", err)
	}
	defer rows.Close()
	var out []i5bJob
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan job: %v", err)
		}
		var p struct {
			Type              string `json:"type"`
			RuleVersion       string `json:"rule_version"`
			InventorySnapshot string `json:"inventory_snapshot"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			t.Fatalf("decode job payload: %v", err)
		}
		out = append(out, i5bJob{Type: p.Type, RuleVersion: p.RuleVersion, Snapshot: p.InventorySnapshot})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read matching.rebuild jobs: %v", err)
	}
	return out
}

// i5bAuditRow is one aggregate audit row with its masked after snapshot.
type i5bAuditRow struct {
	Action    string
	ActorType string
	ActorID   string
	After     string
}

func i5bInventoryAudit(t *testing.T, pool *pgxpool.Pool) []i5bAuditRow {
	t.Helper()
	return i5bAggregateAudit(t, pool, application.AuditAggregateInventory, "")
}

func i5bUserAudit(t *testing.T, pool *pgxpool.Pool, userID string) []i5bAuditRow {
	t.Helper()
	return i5bAggregateAudit(t, pool, application.AuditAggregateUser, userID)
}

func i5bAggregateAudit(t *testing.T, pool *pgxpool.Pool, aggregateType, aggregateID string) []i5bAuditRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	query := `SELECT action, actor_type, actor_id, after FROM audit_events WHERE aggregate_type = $1`
	args := []any{aggregateType}
	if aggregateID != "" {
		query += ` AND aggregate_id = $2`
		args = append(args, aggregateID)
	}
	query += ` ORDER BY occurred_at, id`
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		t.Fatalf("read %s audits: %v", aggregateType, err)
	}
	defer rows.Close()
	var out []i5bAuditRow
	for rows.Next() {
		var r i5bAuditRow
		var after []byte
		if err := rows.Scan(&r.Action, &r.ActorType, &r.ActorID, &after); err != nil {
			t.Fatalf("scan %s audit: %v", aggregateType, err)
		}
		r.After = i5bMaskJSON(t, after)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read %s audits: %v", aggregateType, err)
	}
	return out
}

func i5bRolesOf(t *testing.T, pool *pgxpool.Pool, userID string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role`, userID)
	if err != nil {
		t.Fatalf("read user_roles: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatalf("scan role: %v", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read user_roles: %v", err)
	}
	return out
}
