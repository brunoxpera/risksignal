package main

// I5b exit-criterion proof (c): fault injection (ARCH-006 §8c, NFR-013,
// ch. 5.1/TR-004).
//
// A failing outbox append inside a command must roll back the state change,
// the audit event and the outbox write together — on every channel. Two
// injection styles exercise the same seam:
//
//   - the ARCH-001 §5 seam as the I1b/I4 tests arm it: a test-only decorator
//     over the real OutboxRepo returning a deterministic error (driven through
//     the API channel), proving the state + audit roll back with it; and
//   - a database-level failpoint — a `BEFORE INSERT` trigger on the outbox
//     table that raises — so the *unmodified* API, web and CLI compositions
//     all hit the same failure without any code injection, and every channel is
//     shown to roll back completely.
//
// The import-commit proof stages an upload, then arms the database failpoint:
// the I3 commit's outbox `matching.rebuild` enqueue fails, so the whole commit
// — the additive inventory upserts, the inventory.import audit event and the
// job — rolls back, and the staged record stays `pending` (no committed import
// without its job).
//
// The tests skip when no PostgreSQL is reachable (newTestDB), like every other
// integration test.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	apigen "github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	pggen "github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/application"
)

// i5bArmOutboxFailpoint installs a BEFORE INSERT trigger on the outbox table
// that always raises: any command append on this scratch database fails
// deterministically, with no sleep and no code injection. It is the
// channel-agnostic fault seam of the exit-criterion proof.
func i5bArmOutboxFailpoint(t *testing.T, fixture *i5bFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := fixture.pool.Exec(ctx,
		`CREATE OR REPLACE FUNCTION i5b_fail_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
		 BEGIN RAISE EXCEPTION 'injected outbox append failure'; END; $$`); err != nil {
		t.Fatalf("create failpoint function: %v", err)
	}
	if _, err := fixture.pool.Exec(ctx,
		`CREATE TRIGGER i5b_fail_outbox_trg BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION i5b_fail_outbox()`); err != nil {
		t.Fatalf("create failpoint trigger: %v", err)
	}
}

// TestI5bExitCriteriaFaultInjectionOutboxAppend proves the complete rollback of
// a failing outbox append on every channel.
func TestI5bExitCriteriaFaultInjectionOutboxAppend(t *testing.T) {
	// The ARCH-001 §5 seam as a repository decorator, driven through the API:
	// the injected error propagates unwrapped (infrastructure class) and
	// nothing is written.
	t.Run("api repo seam", func(t *testing.T) {
		f := newI5bFixture(t)
		cause := application.InfraError("outbox.append", errors.New("injected outbox append failure"))
		faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(pggen.New(f.pool)), cause: cause}
		svc := newI5bService(f.pool, newI5bClock(f.base.Add(time.Second)), faulty)
		client, err := apigen.NewClientWithResponses(newI5bAPIStack(t, svc, "security-analyst").URL)
		if err != nil {
			t.Fatalf("api client: %v", err)
		}
		before := i5bNewFaultBaseline(t, f)
		version := f.signal.Version

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := client.SignalCommandWithResponse(ctx, f.signal.ID, apigen.SignalCommandRequest{
			Command: apigen.Acknowledge, ExpectedVersion: &version,
		})
		if err != nil {
			t.Fatalf("API acknowledge: %v", err)
		}
		if resp.StatusCode() != http.StatusInternalServerError {
			t.Fatalf("API acknowledge status = %d (body %s), want 500", resp.StatusCode(), resp.Body)
		}
		if faulty.calls != 1 {
			t.Fatalf("outbox Append calls = %d, want 1 (the fault must hit after the state/audit writes)", faulty.calls)
		}
		before.assertUnchanged(t, f)
	})

	// The database failpoint against the *unmodified* API, web and CLI stacks:
	// the rollback is identical on every channel.
	t.Run("api channel", func(t *testing.T) {
		f := newI5bFixture(t)
		i5bArmOutboxFailpoint(t, f)
		before := i5bNewFaultBaseline(t, f)

		svc := newI5bService(f.pool, newI5bClock(f.base.Add(time.Second)), repo.NewOutboxRepo(pggen.New(f.pool)))
		client, err := apigen.NewClientWithResponses(newI5bAPIStack(t, svc, "security-analyst").URL)
		if err != nil {
			t.Fatalf("api client: %v", err)
		}
		version := before.state.Version
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := client.SignalCommandWithResponse(ctx, f.signal.ID, apigen.SignalCommandRequest{
			Command: apigen.Acknowledge, ExpectedVersion: &version,
		})
		if err != nil {
			t.Fatalf("API acknowledge: %v", err)
		}
		if resp.StatusCode() != http.StatusInternalServerError {
			t.Fatalf("API acknowledge status = %d (body %s), want 500", resp.StatusCode(), resp.Body)
		}
		before.assertUnchanged(t, f)
	})

	t.Run("web channel", func(t *testing.T) {
		f := newI5bFixture(t)
		i5bArmOutboxFailpoint(t, f)
		before := i5bNewFaultBaseline(t, f)

		ch := newI5bWebChannel(t, f, "security-analyst")
		page := i5bWebGet(t, ch.client, ch.srv.URL+"/signals/"+f.signal.ID)
		form := map[string]string{
			"csrf_token":       i5bHiddenField(t, page, "csrf_token"),
			"expected_version": strconv.Itoa(before.state.Version),
		}
		resp := i5bWebPost(t, ch.client, ch.srv.URL+"/signals/"+f.signal.ID+"/acknowledge", form)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("web acknowledge status = %d, want 500", resp.StatusCode)
		}
		before.assertUnchanged(t, f)
	})

	t.Run("cli channel", func(t *testing.T) {
		f := newI5bFixture(t)
		i5bArmOutboxFailpoint(t, f)
		before := i5bNewFaultBaseline(t, f)

		code, stdout, stderr := runCLI(t, cliDBEnv(f.dbURL), "signal", "acknowledge",
			"--signal", f.signal.ID, "--version", strconv.Itoa(before.state.Version), "--as", i5bAnalystSubject, "--output", "json")
		if code == exitOK {
			t.Fatalf("CLI acknowledge succeeded, want failure (stdout: %s)", stdout)
		}
		if code != exitInfrastructure {
			t.Fatalf("CLI acknowledge exit = %d, want %d (stderr: %s)", code, exitInfrastructure, stderr)
		}
		before.assertUnchanged(t, f)
	})
}

// TestI5bExitCriteriaFaultInjectionImportCommit proves that an import commit
// whose matching.rebuild enqueue fails rolls the whole staged commit back.
func TestI5bExitCriteriaFaultInjectionImportCommit(t *testing.T) {
	f := newI5bFixture(t)
	svc := newI5bService(f.pool, newI5bClock(f.base.Add(time.Second)), repo.NewOutboxRepo(pggen.New(f.pool)))
	client, err := apigen.NewClientWithResponses(newI5bAPIStack(t, svc, "administrator").URL)
	if err != nil {
		t.Fatalf("api client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Stage the upload (writes only the staging record, no outbox).
	rows := []string{inventoryITVendorRow("fault-a1", "Fault-Host", "acme", "portal", "9.9.9")}
	csv := inventoryITHeader + "\n" + strings.Join(rows, "\n") + "\n"
	upload, err := client.CreateInventoryImportWithBodyWithResponse(ctx, "text/csv", strings.NewReader(csv))
	if err != nil || upload.StatusCode() != http.StatusOK || upload.JSON200 == nil {
		t.Fatalf("stage upload = %v (err %v), want 200", upload, err)
	}
	importID := upload.JSON200.Id

	assetsBefore := i5bAssetsSnapshot(t, f.pool)
	componentsBefore := i5bComponentsSnapshot(t, f.pool)
	auditsBefore := len(i5bInventoryAudit(t, f.pool))

	// Arm the failpoint: the commit's matching.rebuild enqueue now fails.
	i5bArmOutboxFailpoint(t, f)

	commit, err := client.CommitInventoryImportWithResponse(ctx, importID)
	if err != nil {
		t.Fatalf("API commit: %v", err)
	}
	if commit.StatusCode() != http.StatusInternalServerError {
		t.Fatalf("commit status = %d (body %s), want 500", commit.StatusCode(), commit.Body)
	}

	// The whole staged commit rolled back: no inventory upsert, no
	// inventory.import audit, no matching.rebuild job, and the record stays
	// pending (no committed import without its job).
	if got := i5bAssetsSnapshot(t, f.pool); !equalStrings(got, assetsBefore) {
		t.Fatalf("assets after failed commit = %v, want unchanged %v", got, assetsBefore)
	}
	if got := i5bComponentsSnapshot(t, f.pool); !equalStrings(got, componentsBefore) {
		t.Fatalf("components after failed commit = %v, want unchanged %v", got, componentsBefore)
	}
	if got := len(i5bInventoryAudit(t, f.pool)); got != auditsBefore {
		t.Fatalf("inventory audit rows after failed commit = %d, want %d", got, auditsBefore)
	}
	if got := i5bRebuildJobs(t, f.pool); len(got) != 0 {
		t.Fatalf("matching.rebuild jobs after failed commit = %v, want none", got)
	}
	if status := i5bImportStatus(t, f, importID); status != string(application.InventoryImportPending) {
		t.Fatalf("staged import status after failed commit = %q, want pending", status)
	}
}

// i5bFaultBaseline is the state a command must leave untouched when its outbox
// append fails.
type i5bFaultBaseline struct {
	state  i5bState
	audits int
	outbox int
}

func i5bNewFaultBaseline(t *testing.T, f *i5bFixture) i5bFaultBaseline {
	t.Helper()
	ch := newI5bCLIChannel(t, f, i5bAnalystSubject)
	return i5bFaultBaseline{
		state:  i5bReadState(t, ch),
		audits: countSignalAudits(t, context.Background(), f.pool, f.signal.ID),
		outbox: countTableRows(t, f.pool, "outbox"),
	}
}

func (b i5bFaultBaseline) assertUnchanged(t *testing.T, f *i5bFixture) {
	t.Helper()
	ch := newI5bCLIChannel(t, f, i5bAnalystSubject)
	if got := i5bReadState(t, ch); got != b.state {
		t.Fatalf("state after failed command = %+v, want unchanged %+v", got, b.state)
	}
	if got := countSignalAudits(t, context.Background(), f.pool, f.signal.ID); got != b.audits {
		t.Fatalf("audit rows after failed command = %d, want unchanged %d", got, b.audits)
	}
	if got := countTableRows(t, f.pool, "outbox"); got != b.outbox {
		t.Fatalf("outbox rows after failed command = %d, want unchanged %d", got, b.outbox)
	}
}

// i5bImportStatus reads a staged import's lifecycle status.
func i5bImportStatus(t *testing.T, f *i5bFixture, id string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var status string
	if err := f.pool.QueryRow(ctx, `SELECT status FROM inventory_imports WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatalf("read import status: %v", err)
	}
	return status
}

// equalStrings reports whether two string slices are equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
