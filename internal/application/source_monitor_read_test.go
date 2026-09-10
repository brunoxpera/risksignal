package application_test

// Unit tests of the DEV-110 ListSourceStatus read use case (ARCH-006 §3.1):
// the permission gate (sources.manage — deny-by-default, an
// administrator-only grant) and the derived monitor projection (data age from
// the latest successful run's basis, the stale/degraded verdict, the latest
// run's error count and rate-limit flag, the open quarantine count). All run
// against the in-memory fakes; no database and no transaction.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedSourceStatus appends one committed source-monitor record to the fake
// store.
func seedSourceStatus(h *harness, rec application.SourceStatusRecord) {
	h.db.sourceStatus = append(h.db.sourceStatus, rec)
}

func TestListSourceStatusRendersProjection(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	finished := fixedNow.Add(-3 * time.Hour)
	seedSourceStatus(h, application.SourceStatusRecord{
		ID: "src-1", Name: "nvd", Type: application.SourceTypeNVD, Enabled: true,
		Schedule: application.ScheduleDaily, OpenQuarantine: 2,
		LastRun: &application.SourceRunSummary{
			Status: application.SourceRunStatusFailed, StartedAt: finished, FinishedAt: finished,
			Error: application.RateLimitedErrorText, Counters: application.SourceRunCounters{Records: 5, Errors: 2},
		},
		Succeeded: &application.SourceRunSummary{
			Status: application.SourceRunStatusSucceeded, StartedAt: finished, FinishedAt: finished,
		},
	})

	res, err := h.svc.ListSourceStatus(context.Background(), application.ListSourceStatusInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("ListSourceStatus: %v", err)
	}
	if len(res.Sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(res.Sources))
	}
	s := res.Sources[0]
	if s.Type != string(application.SourceTypeNVD) || s.Name != "nvd" || !s.Enabled {
		t.Fatalf("identity = %+v", s)
	}
	if s.LastRunStatus != string(application.SourceRunStatusFailed) {
		t.Fatalf("last run status = %q", s.LastRunStatus)
	}
	if s.ErrorCount != 2 {
		t.Fatalf("error count = %d, want 2", s.ErrorCount)
	}
	if !s.RateLimited {
		t.Fatalf("rate-limit flag not set for the rate-limited run")
	}
	if s.OpenQuarantine != 2 {
		t.Fatalf("open quarantine = %d, want 2", s.OpenQuarantine)
	}
	if !s.HasDataAge || s.DataAge != 3*time.Hour {
		t.Fatalf("data age = %v (has=%v), want 3h", s.DataAge, s.HasDataAge)
	}
	if s.Degraded {
		t.Fatalf("a 3h-old daily source must not be degraded")
	}
}

func TestListSourceStatusDegradedAndCursorBasis(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	// A daily source whose last successful run is 50h old is stale
	// (data age > 2 × 24h).
	stale := fixedNow.Add(-50 * time.Hour)
	seedSourceStatus(h, application.SourceStatusRecord{
		ID: "src-stale", Name: "kev", Type: application.SourceTypeKEV, Enabled: true,
		Schedule: application.ScheduleDaily,
		Succeeded: &application.SourceRunSummary{
			Status: application.SourceRunStatusSucceeded, StartedAt: stale, FinishedAt: stale,
		},
	})
	// An incremental source whose committed cursor last_modified is 1h old:
	// the cursor (not finished_at) is the data-age basis.
	cursorFinished := fixedNow.Add(-10 * time.Hour)
	cursor, _ := json.Marshal(map[string]string{"last_modified": fixedNow.Add(-time.Hour).UTC().Format(time.RFC3339)})
	seedSourceStatus(h, application.SourceStatusRecord{
		ID: "src-cursor", Name: "nvd", Type: application.SourceTypeNVD, Enabled: true,
		Schedule: application.ScheduleHourly,
		Succeeded: &application.SourceRunSummary{
			Status: application.SourceRunStatusSucceeded, StartedAt: cursorFinished,
			FinishedAt: cursorFinished, CursorAfter: cursor,
		},
	})

	res, err := h.svc.ListSourceStatus(context.Background(), application.ListSourceStatusInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("ListSourceStatus: %v", err)
	}
	byID := map[string]application.SourceStatus{}
	for _, s := range res.Sources {
		byID[s.ID] = s
	}
	if !byID["src-stale"].Degraded {
		t.Fatalf("a 50h-old daily source must be degraded")
	}
	// The hourly source's age derives from the cursor (1h), and the hourly
	// stale threshold is 2h, so it is not degraded.
	c := byID["src-cursor"]
	if !c.HasDataAge || c.DataAge != time.Hour {
		t.Fatalf("cursor-based data age = %v (has=%v), want 1h", c.DataAge, c.HasDataAge)
	}
	if c.Degraded {
		t.Fatalf("a 1h-old hourly source must not be degraded")
	}
}

func TestListSourceStatusDeniesRolelessUser(t *testing.T) {
	h := newHarness(t)
	seedSourceStatus(h, application.SourceStatusRecord{ID: "src-1", Name: "nvd"})
	h.users.add("nobody", "Nobody") // no roles ⇒ deny-by-default

	_, err := h.svc.ListSourceStatus(context.Background(), application.ListSourceStatusInput{Actor: userActor("nobody")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("role-less ListSourceStatus = %v (%s), want forbidden", err, kind)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("denied read opened %d transactions, want 0", len(h.runner.txs))
	}
}

func TestListSourceStatusDeniesNonAdminRole(t *testing.T) {
	h := newHarness(t)
	seedSourceStatus(h, application.SourceStatusRecord{ID: "src-1", Name: "nvd"})
	// The Analyst holds no sources.manage ⇒ the admin-only read is denied.
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)

	_, err := h.svc.ListSourceStatus(context.Background(), application.ListSourceStatusInput{Actor: userActor("analyst")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("analyst ListSourceStatus = %v (%s), want forbidden", err, kind)
	}
}
