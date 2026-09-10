package main

// Integration tests of the WP-5b.08 (I5b) signal/user CLI subcommands
// (DEV-105, closing the DEV-103 review finding): one --output json success
// round-trip per new subcommand, asserting the schema-stable envelope and the
// command result payload. They run against a real, short-lived PostgreSQL
// behind the production postgres repositories; the auth subcommands (no
// database) are covered by cli_i5b_test.go. The tests skip when no PostgreSQL
// is reachable (newTestDB), so `go test ./...` stays green without the
// compose environment.

import (
	"strconv"
	"testing"
)

// Seeded identities (migration 00009) referenced by the user-administration
// round-trips: the auditor (single security role) and the product owner.
const (
	i5bAnalystUserID      = "e5a00000-0000-4000-8000-000000000002"
	i5bAuditorUserID      = "e5a00000-0000-4000-8000-000000000005"
	i5bProductOwnerUserID = "e5a00000-0000-4000-8000-000000000006"
)

// runJSONOK runs one CLI command with --output json, asserts the exit-0
// schema-stable envelope for wantCommand and returns the decoded envelope.
func runJSONOK(t *testing.T, env map[string]string, wantCommand string, args ...string) rawEnvelope {
	t.Helper()
	code, stdout, stderr := runCLI(t, env, append(args, "--output", "json")...)
	if code != exitOK {
		t.Fatalf("risksignal %s: exit code = %d, want 0 (stdout: %s, stderr: %s)", wantCommand, code, stdout, stderr)
	}
	return assertEnvelopeOK(t, wantCommand, stdout, stderr)
}

// hasRole reports whether roles contains want.
func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// TestI5bSignalCommandsJSONRoundTrip drives the new signal subcommands through
// the CLI against a real database, one --output json success round-trip each,
// threading the optimistic-lock version from command to command.
func TestI5bSignalCommandsJSONRoundTrip(t *testing.T) {
	_, dbURL, sig := parityFixture(t)
	env := cliDBEnv(dbURL)
	const as = "local::local-developer"

	// list + show (signals.read).
	list := runJSONOK(t, env, "signal list", "signal", "list", "--as", as)
	var page signalListResult
	decodeJSONStrict(t, string(list.Result), &page)
	if len(page.Data) == 0 {
		t.Fatal("signal list returned no signals, want the seeded fixture")
	}
	show := runJSONOK(t, env, "signal show", "signal", "show", "--signal", sig.ID, "--as", as)
	var view signalView
	decodeJSONStrict(t, string(show.Result), &view)
	if view.ID != sig.ID || view.Status == "" {
		t.Fatalf("signal show result = %+v, want the signal %s", view, sig.ID)
	}

	version := sig.Version

	// assign (version-guarded).
	assign := runJSONOK(t, env, "signal assign", "signal", "assign",
		"--signal", sig.ID, "--owner", i5bAnalystUserID, "--version", strconv.Itoa(version), "--as", as)
	var assignRes signalCommandResult
	decodeJSONStrict(t, string(assign.Result), &assignRes)
	if assignRes.Command != signalCmdAssignOwner || assignRes.OwnerID == nil || *assignRes.OwnerID != i5bAnalystUserID {
		t.Fatalf("assign result = %+v, want command %q owner %s", assignRes, signalCmdAssignOwner, i5bAnalystUserID)
	}
	if assignRes.Version <= version {
		t.Fatalf("assign version = %d, want > %d", assignRes.Version, version)
	}
	version = assignRes.Version

	// transition (version-guarded).
	transition := runJSONOK(t, env, "signal transition", "signal", "transition",
		"--signal", sig.ID, "--to", "in_review", "--version", strconv.Itoa(version), "--as", as)
	var transitionRes signalCommandResult
	decodeJSONStrict(t, string(transition.Result), &transitionRes)
	if transitionRes.Command != signalCmdChangeStatus || transitionRes.Status != "in_review" {
		t.Fatalf("transition result = %+v, want command %q status in_review", transitionRes, signalCmdChangeStatus)
	}
	version = transitionRes.Version

	// comment (append-only, not version-guarded).
	comment := runJSONOK(t, env, "signal comment", "signal", "comment",
		"--signal", sig.ID, "--comment", "initial triage note", "--as", as)
	var commentRes signalCommandResult
	decodeJSONStrict(t, string(comment.Result), &commentRes)
	if commentRes.Command != signalCmdAddComment || commentRes.Status != "in_review" {
		t.Fatalf("comment result = %+v, want command %q on in_review signal", commentRes, signalCmdAddComment)
	}

	// override (version-guarded) — establishes the override the revert reverts.
	override := runJSONOK(t, env, "signal override", "signal", "override",
		"--signal", sig.ID, "--priority", "P2", "--reason", "compensating control",
		"--version", strconv.Itoa(version), "--as", as)
	var overrideRes signalCommandResult
	decodeJSONStrict(t, string(override.Result), &overrideRes)
	if overrideRes.Command != signalCmdOverridePriority || overrideRes.Priority != "P2" {
		t.Fatalf("override result = %+v, want command %q priority P2", overrideRes, signalCmdOverridePriority)
	}
	version = overrideRes.Version

	// revert (version-guarded).
	revert := runJSONOK(t, env, "signal revert", "signal", "revert",
		"--signal", sig.ID, "--version", strconv.Itoa(version), "--as", as)
	var revertRes signalCommandResult
	decodeJSONStrict(t, string(revert.Result), &revertRes)
	if revertRes.Command != signalCmdRevertPriority {
		t.Fatalf("revert result = %+v, want command %q", revertRes, signalCmdRevertPriority)
	}

	// pause + resume (clock-state guarded, not version-guarded).
	pause := runJSONOK(t, env, "signal pause", "signal", "pause",
		"--signal", sig.ID, "--target", "decision", "--reason", "vendor outage", "--as", as)
	var pauseRes signalCommandResult
	decodeJSONStrict(t, string(pause.Result), &pauseRes)
	if pauseRes.Command != signalCmdPauseSLA || pauseRes.Target == nil || *pauseRes.Target != "decision" {
		t.Fatalf("pause result = %+v, want command %q target decision", pauseRes, signalCmdPauseSLA)
	}
	resume := runJSONOK(t, env, "signal resume", "signal", "resume",
		"--signal", sig.ID, "--target", "decision", "--reason", "vendor restored", "--as", as)
	var resumeRes signalCommandResult
	decodeJSONStrict(t, string(resume.Result), &resumeRes)
	if resumeRes.Command != signalCmdResumeSLA {
		t.Fatalf("resume result = %+v, want command %q", resumeRes, signalCmdResumeSLA)
	}
}

// TestI5bUserCommandsJSONRoundTrip drives the user/role administration
// subcommands through the CLI against a real database, one --output json
// success round-trip each.
func TestI5bUserCommandsJSONRoundTrip(t *testing.T) {
	_, dbURL, _ := parityFixture(t)
	env := cliDBEnv(dbURL)
	const as = "local::local-developer"

	list := runJSONOK(t, env, "user list", "user", "list", "--as", as)
	var page userListResult
	decodeJSONStrict(t, string(list.Result), &page)
	if len(page.Data) == 0 {
		t.Fatal("user list returned no users, want the seeded identities")
	}

	// grant a role the auditor does not hold, then revoke it.
	grant := runJSONOK(t, env, "user grant", "user", "grant",
		"--user", i5bAuditorUserID, "--role", "product_owner", "--as", as)
	var granted userView
	decodeJSONStrict(t, string(grant.Result), &granted)
	if granted.ID != i5bAuditorUserID || !hasRole(granted.Roles, "product_owner") {
		t.Fatalf("grant result = %+v, want product_owner granted to %s", granted, i5bAuditorUserID)
	}

	revoke := runJSONOK(t, env, "user revoke", "user", "revoke",
		"--user", i5bAuditorUserID, "--role", "product_owner", "--as", as)
	var revoked userView
	decodeJSONStrict(t, string(revoke.Result), &revoked)
	if revoked.ID != i5bAuditorUserID || hasRole(revoked.Roles, "product_owner") {
		t.Fatalf("revoke result = %+v, want product_owner revoked from %s", revoked, i5bAuditorUserID)
	}

	// deactivate requires and accepts --yes; the user is marked deactivated.
	deactivate := runJSONOK(t, env, "user deactivate", "user", "deactivate",
		"--user", i5bProductOwnerUserID, "--yes", "--as", as)
	var deactivated userView
	decodeJSONStrict(t, string(deactivate.Result), &deactivated)
	if deactivated.ID != i5bProductOwnerUserID || deactivated.DeactivatedAt == nil {
		t.Fatalf("deactivate result = %+v, want %s deactivated", deactivated, i5bProductOwnerUserID)
	}
}
