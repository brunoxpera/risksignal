package worker

// Unit tests for the I6 job handlers' decode/classify paths (ARCH-007 §1.2/
// §2.2, WP-6.06 / DEV-118): a malformed or mismatched payload is a permanent
// failure (dead-letters), an infrastructure failure of the use case is
// retryable (Retry) and a delivered job drives the runner once.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
)

type stubExportRunner struct {
	calls int
	got   application.GenerateExportInput
	res   application.GenerateExportResult
	err   error
}

func (s *stubExportRunner) GenerateExport(_ context.Context, in application.GenerateExportInput) (application.GenerateExportResult, error) {
	s.calls++
	s.got = in
	return s.res, s.err
}

func testJobsLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestExportJobsHandleDelivers(t *testing.T) {
	runner := &stubExportRunner{res: application.GenerateExportResult{ExportID: "e1", Status: application.ExportStatusCompleted}}
	j := &ExportJobs{runner: runner, logger: testJobsLogger()}

	payload, _ := json.Marshal(application.ExportGeneratePayload{
		EventID: "ev1", Type: application.EventTypeExportGenerate, ExportID: "e1",
	})
	if err := j.handle(context.Background(), ClaimedEvent{ID: "row1", Type: application.EventTypeExportGenerate, Payload: payload}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if runner.calls != 1 || runner.got.ExportID != "e1" {
		t.Fatalf("runner calls = %d, got = %+v", runner.calls, runner.got)
	}
}

func TestExportJobsHandleRejectsMalformedPayload(t *testing.T) {
	j := &ExportJobs{runner: &stubExportRunner{}, logger: testJobsLogger()}
	if err := j.handle(context.Background(), ClaimedEvent{Type: application.EventTypeExportGenerate, Payload: []byte("not json")}); err == nil {
		t.Fatal("a malformed payload was accepted")
	}
	if err := j.handle(context.Background(), ClaimedEvent{Type: application.EventTypeExportGenerate, Payload: []byte(`{"type":"other","export_id":"e1"}`)}); err == nil {
		t.Fatal("a mismatched payload type was accepted")
	}
}

func TestExportJobsHandleClassifiesInfraAsRetryable(t *testing.T) {
	runner := &stubExportRunner{err: application.InfraError("generate_export", errors.New("db down"))}
	j := &ExportJobs{runner: runner, logger: testJobsLogger()}
	payload, _ := json.Marshal(application.ExportGeneratePayload{
		EventID: "ev1", Type: application.EventTypeExportGenerate, ExportID: "e1",
	})
	err := j.handle(context.Background(), ClaimedEvent{Type: application.EventTypeExportGenerate, Payload: payload})
	if !isRetryable(err) {
		t.Fatalf("err = %v, want a retryable (Retry-wrapped) error", err)
	}
}

type stubRetentionRunner struct {
	calls int
	res   application.ExecuteRetentionResult
	err   error
}

func (s *stubRetentionRunner) ExecuteRetention(_ context.Context, _ application.ExecuteRetentionInput) (application.ExecuteRetentionResult, error) {
	s.calls++
	return s.res, s.err
}

func TestRetentionJobsHandleDelivers(t *testing.T) {
	runner := &stubRetentionRunner{res: application.ExecuteRetentionResult{RunID: "r1", Status: application.RetentionStatusCompleted}}
	j := &RetentionJobs{runner: runner, logger: testJobsLogger()}
	payload, _ := json.Marshal(application.RetentionExecutePayload{
		EventID: "ev1", Type: application.EventTypeRetentionExecute, RunID: "r1",
	})
	if err := j.handle(context.Background(), ClaimedEvent{Type: application.EventTypeRetentionExecute, Payload: payload}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
}

func TestRetentionJobsHandleRejectsMalformedPayload(t *testing.T) {
	j := &RetentionJobs{runner: &stubRetentionRunner{}, logger: testJobsLogger()}
	if err := j.handle(context.Background(), ClaimedEvent{Type: application.EventTypeRetentionExecute, Payload: []byte("not json")}); err == nil {
		t.Fatal("a malformed payload was accepted")
	}
}

func TestRetentionJobsHandleClassifiesPermanent(t *testing.T) {
	runner := &stubRetentionRunner{err: application.NotFoundError("execute_retention", errors.New("run not found"))}
	j := &RetentionJobs{runner: runner, logger: testJobsLogger()}
	payload, _ := json.Marshal(application.RetentionExecutePayload{
		EventID: "ev1", Type: application.EventTypeRetentionExecute, RunID: "r1",
	})
	err := j.handle(context.Background(), ClaimedEvent{Type: application.EventTypeRetentionExecute, Payload: payload})
	if err == nil || isRetryable(err) {
		t.Fatalf("err = %v, want a permanent (non-retryable) error", err)
	}
}
