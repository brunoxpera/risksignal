// `risksignal maintenance retention` and
// `risksignal maintenance identity-pseudonymize` (concept ch. 11.3,
// ARCH-007 §2.2/§3, WP-6.07 / DEV-119): the CLI form of the governed
// retention and pseudonymisation operations. They drive the same application
// use cases the API retention-run surface binds:
//
//	POST /api/v1/retention/runs              (retention --dry-run)
//	GET  /api/v1/retention/runs              (retention --list)
//	POST /api/v1/retention/runs/{id}/approve (retention --approve)
//	(identity-pseudonymize is CLI/operator-only, ch. 11.3)
//
// with the same in-command gates and the same audit — the application layer is
// the gate of record, so no channel bypasses it (ARCH-005 §5, NFR-013 channel
// parity). Retention is governed: a dry-run is mandatory, only the Product
// Owner (settings.approve) may approve the deletion (four-eyes) and the
// approval itself enqueues the execution. All commands are strictly
// non-interactive (ch. 11.3): the parameters are complete command-line
// arguments, never a dialogue. The destructive steps (approve, the real
// pseudonymisation) require the explicit --yes/--commit confirmation flag; the
// CLI never prompts. The acting identity is selected with --as; it defaults to
// the configured auth.bypass_principal in the local namespace.

package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// retentionCommandTimeout bounds one retention/pseudonymisation command: a
// read plus at most one guarded transaction (the dry-run stores one report
// row, the approval one flip + one outbox append).
const retentionCommandTimeout = 60 * time.Second

// cmdRetention runs `risksignal maintenance retention
// --dry-run|--list|--approve <id> [--stage <s>] [--reason <t>] [--yes]
// [--as <subject>]`. Exactly one of --dry-run, --list and --approve selects
// the mode; --approve is destructive (it authorises the deletion) and requires
// --yes plus a reason.
func (e *cmdEnv) cmdRetention(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal maintenance retention --dry-run|--list|--approve <id> [--stage <s>] [--reason <t>] [--yes] [--as <subject>]\n"+
		"  --dry-run        scan + count the due signals and store a counts-only report (reads only)\n"+
		"  --list           print the stored retention-run report\n"+
		"  --approve <id>   approve (or --reject) a stored dry-run (settings.approve, destructive)\n"+
		"  --stage          dry-run stage: pseudonymise | delete (default delete)\n"+
		"  --reason         mandatory, non-blank approval reason\n"+
		"  --yes            confirm the destructive approval (mandatory)")
	dryRun := fs.Bool("dry-run", false, "scan + count the due signals and store a counts-only report (reads only)")
	list := fs.Bool("list", false, "print the stored retention-run report")
	approve := fs.String("approve", "", "the dry_run run id to approve (destructive)")
	reject := fs.Bool("reject", false, "reject the run instead of approving it")
	stage := fs.String("stage", "", "dry-run stage: pseudonymise | delete")
	reason := fs.String("reason", "", "mandatory, non-blank approval reason")
	yes := fs.Bool("yes", false, "confirm the destructive approval")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	modes := 0
	if *dryRun {
		modes++
	}
	if *list {
		modes++
	}
	if strings.TrimSpace(*approve) != "" {
		modes++
	}
	if modes != 1 {
		return e.fail(exitValidation, classValidation, "exactly one of --dry-run, --list or --approve is required")
	}
	if strings.TrimSpace(*approve) != "" {
		if strings.TrimSpace(*reason) == "" {
			return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank for --approve")
		}
		if !*yes {
			return e.fail(exitValidation, classValidation, "retention --approve authorises deletion and is destructive; pass --yes to confirm (the CLI never prompts)")
		}
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), retentionCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveSignalActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}

	switch {
	case *list:
		runs, err := svc.ListRetentionRuns(ctx, application.ListRetentionRunsInput{Actor: actor})
		if err != nil {
			return applicationErrorOutcome(err)
		}
		views := make([]retentionRunView, 0, len(runs))
		for _, r := range runs {
			views = append(views, retentionRunViewOf(r))
		}
		result := retentionRunListView{Data: views}
		if e.format == formatText {
			printRetentionRunList(e.stdout, result)
		}
		return e.ok(result)

	case strings.TrimSpace(*approve) != "":
		decided, err := svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{
			RunID:  strings.TrimSpace(*approve),
			Reason: *reason,
			Reject: *reject,
			Actor:  actor,
		})
		if err != nil {
			return applicationErrorOutcome(err)
		}
		view := retentionRunView{ID: decided.RunID, Status: string(decided.Status), ApprovedBy: stringPtrOrNil(decided.ApprovedBy)}
		if !decided.ApprovedAt.IsZero() {
			at := decided.ApprovedAt
			view.ApprovedAt = &at
		}
		if e.format == formatText {
			fmt.Fprintf(e.stdout, "retention run %s: %s by %s\n", view.ID, view.Status, decided.ApprovedBy)
		}
		return e.ok(view)

	default: // --dry-run
		in := application.RunRetentionDryRunInput{Actor: actor}
		if s := strings.TrimSpace(*stage); s != "" {
			in.Stage = application.RetentionStage(s)
		}
		res, err := svc.RunRetentionDryRun(ctx, in)
		if err != nil {
			return applicationErrorOutcome(err)
		}
		view := retentionRunViewOf(res.Run)
		if e.format == formatText {
			fmt.Fprintf(e.stdout, "retention dry-run %s: %d candidate(s), %d held, %d to delete, %d to pseudonymise (cutoff %s)\n",
				view.ID, view.DryRun.Candidates, view.DryRun.Held, view.DryRun.ToDelete, view.DryRun.ToPseudonymise,
				res.Cutoff.UTC().Format(time.RFC3339))
			for _, held := range res.Held {
				fmt.Fprintf(e.stdout, "  held: %s (%s)\n", held.SignalID, held.HoldReason)
			}
		}
		return e.ok(view)
	}
}

// cmdIdentityPseudonymize runs `risksignal maintenance identity-pseudonymize
// --user <id> [--reason <text>] [--commit|--yes] [--as <subject>]`. Without
// --commit (or its alias --yes) it is the mandatory dry run: it reports the
// per-target redaction counts and changes nothing (ch. 11.3). With a commit
// flag the real, audited pseudonymisation runs and --reason is mandatory.
func (e *cmdEnv) cmdIdentityPseudonymize(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal maintenance identity-pseudonymize --user <id> [--reason <text>] [--commit|--yes] [--as <subject>]\n"+
		"  dry run by default: report the per-target redaction counts, nothing written.\n"+
		"  --commit (or its alias --yes) runs the real, audited pseudonymisation; --reason is\n"+
		"  then mandatory (ADR-014: an unlogged pseudonymisation would be worse than none).")
	user := fs.String("user", "", "the user id to pseudonymise (mandatory)")
	reason := fs.String("reason", "", "documented reason (mandatory for a real run)")
	commit := fs.Bool("commit", false, "run the real, audited pseudonymisation")
	yes := fs.Bool("yes", false, "alias of --commit (non-interactive confirmation)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*user) == "" {
		return e.fail(exitValidation, classValidation, "--user is mandatory (the user id to pseudonymise)")
	}
	if (*commit || *yes) && strings.TrimSpace(*reason) == "" {
		return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank for a real pseudonymisation")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), retentionCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveSignalActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}
	res, err := svc.PseudonymizeIdentity(ctx, application.PseudonymizeIdentityInput{
		UserID: *user,
		DryRun: !*commit && !*yes,
		Reason: *reason,
		Actor:  actor,
	})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	view := pseudonymiseViewOf(res)
	if e.format == formatText {
		if view.DryRun {
			fmt.Fprintf(e.stdout, "identity-pseudonymize (dry run) %s: would clear %d display name(s), redact %d comment(s), %d override reason(s), %d snapshot reason(s)\n",
				view.UserID, view.Redaction.DisplayNamesCleared, view.Redaction.CommentBodiesRedacted, view.Redaction.OverrideReasonsRedacted, view.Redaction.SnapshotReasonsRedacted)
		} else {
			fmt.Fprintf(e.stdout, "identity-pseudonymize %s: cleared %d display name(s), redacted %d comment(s), %d override reason(s), %d snapshot reason(s)\n",
				view.UserID, view.Redaction.DisplayNamesCleared, view.Redaction.CommentBodiesRedacted, view.Redaction.OverrideReasonsRedacted, view.Redaction.SnapshotReasonsRedacted)
		}
	}
	return e.ok(view)
}

// retentionRunView is the machine-readable retention run (mirrors the API
// RetentionRun; the approval/execution stamps are null until set).
type retentionRunView struct {
	ID                 string               `json:"id"`
	PolicyID           string               `json:"policy_id"`
	Stage              string               `json:"stage"`
	Cutoff             time.Time            `json:"cutoff"`
	PartitionKey       string               `json:"partition_key"`
	Status             string               `json:"status"`
	DryRun             *retentionDryRunView `json:"dry_run"`
	ApprovedBy         *string              `json:"approved_by"`
	ApprovedAt         *time.Time           `json:"approved_at"`
	ApprovalReason     *string              `json:"approval_reason"`
	StartedAt          *time.Time           `json:"started_at"`
	FinishedAt         *time.Time           `json:"finished_at"`
	PseudonymisedCount int                  `json:"pseudonymised_count"`
	DeletedCount       int                  `json:"deleted_count"`
	FailedCount        int                  `json:"failed_count"`
	LastError          *string              `json:"last_error"`
}

// retentionDryRunView is the counts-only dry-run report of a run.
type retentionDryRunView struct {
	Candidates     int `json:"candidates"`
	Held           int `json:"held"`
	ToPseudonymise int `json:"to_pseudonymise"`
	ToDelete       int `json:"to_delete"`
}

// retentionRunListView is the machine-readable retention-run page.
type retentionRunListView struct {
	Data []retentionRunView `json:"data"`
}

// retentionRunViewOf maps a stored retention run onto the wire view.
func retentionRunViewOf(r application.RetentionRun) retentionRunView {
	view := retentionRunView{
		ID:                 r.ID,
		PolicyID:           r.PolicyID,
		Stage:              string(r.Stage),
		Cutoff:             r.Cutoff,
		PartitionKey:       r.PartitionKey,
		Status:             string(r.Status),
		PseudonymisedCount: r.Pseudonymised,
		DeletedCount:       r.Deleted,
		FailedCount:        r.Failed,
	}
	if r.DryRun != nil {
		view.DryRun = &retentionDryRunView{
			Candidates:     r.DryRun.Candidates,
			Held:           r.DryRun.Held,
			ToPseudonymise: r.DryRun.ToPseudonymise,
			ToDelete:       r.DryRun.ToDelete,
		}
	}
	if r.ApprovedBy != "" {
		view.ApprovedBy = stringPtrOrNil(r.ApprovedBy)
	}
	if !r.ApprovedAt.IsZero() {
		at := r.ApprovedAt
		view.ApprovedAt = &at
	}
	if r.ApprovalReason != "" {
		view.ApprovalReason = stringPtrOrNil(r.ApprovalReason)
	}
	if !r.StartedAt.IsZero() {
		at := r.StartedAt
		view.StartedAt = &at
	}
	if !r.FinishedAt.IsZero() {
		at := r.FinishedAt
		view.FinishedAt = &at
	}
	if r.LastError != "" {
		view.LastError = stringPtrOrNil(r.LastError)
	}
	return view
}

// pseudonymiseView is the machine-readable pseudonymisation result.
type pseudonymiseView struct {
	UserID    string                    `json:"user_id"`
	DryRun    bool                      `json:"dry_run"`
	Redaction pseudonymiseRedactionView `json:"redaction"`
}

// pseudonymiseRedactionView is the per-target redaction counts.
type pseudonymiseRedactionView struct {
	DisplayNamesCleared     int `json:"display_names_cleared"`
	CommentBodiesRedacted   int `json:"comment_bodies_redacted"`
	OverrideReasonsRedacted int `json:"override_reasons_redacted"`
	SnapshotReasonsRedacted int `json:"snapshot_reasons_redacted"`
}

// pseudonymiseViewOf maps a pseudonymisation result onto the wire view.
func pseudonymiseViewOf(res application.PseudonymizeIdentityResult) pseudonymiseView {
	return pseudonymiseView{
		UserID: res.UserID,
		DryRun: res.DryRun,
		Redaction: pseudonymiseRedactionView{
			DisplayNamesCleared:     res.Redaction.DisplayNamesCleared,
			CommentBodiesRedacted:   res.Redaction.CommentBodiesRedacted,
			OverrideReasonsRedacted: res.Redaction.OverrideReasonsRedacted,
			SnapshotReasonsRedacted: res.Redaction.SnapshotReasonsRedacted,
		},
	}
}

// printRetentionRunList renders the retention-run report as human-readable text.
func printRetentionRunList(w io.Writer, r retentionRunListView) {
	fmt.Fprintf(w, "%d retention run(s):\n", len(r.Data))
	for _, run := range r.Data {
		held, toDelete, toPseudo := 0, 0, 0
		if run.DryRun != nil {
			held, toDelete, toPseudo = run.DryRun.Held, run.DryRun.ToDelete, run.DryRun.ToPseudonymise
		}
		fmt.Fprintf(w, "  %s %s [%s] cutoff=%s held=%d delete=%d pseudonymise=%d deleted=%d pseudonymised=%d failed=%d\n",
			run.ID, run.PolicyID, run.Status, run.Cutoff.UTC().Format(time.RFC3339),
			held, toDelete, toPseudo, run.DeletedCount, run.PseudonymisedCount, run.FailedCount)
	}
}

// stringPtrOrNil returns a pointer to a copy of s, or nil for the empty string
// (the generated nullable fields are absent for an empty value).
func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
