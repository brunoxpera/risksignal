// `risksignal user ...` (concept ch. 11.3, ARCH-006 §3.3/§5, WP-5b.08): the
// user/role administration surface of the CLI. It drives the same application
// use cases as the API endpoints
//
//	GET   /api/v1/users
//	PATCH /api/v1/users/{id}/roles
//	POST  /api/v1/users/{id}/deactivate
//
// with the same in-command permission gate (users.roles.manage, deny-by-
// default) and the same audit — the application layer is the gate of record,
// so no channel bypasses it (ARCH-005 §5, NFR-013 channel parity). The
// command vocabulary is 1:1 with the API:
//
//	risksignal user list      [--limit <n>] [--cursor <c>]           ListUsers
//	risksignal user grant     --user <id> --role <role>              GrantRole
//	risksignal user revoke    --user <id> --role <role>              RevokeRole
//	risksignal user deactivate --user <id> --yes                     DeactivateUser
//
// The commands are strictly non-interactive (ch. 11.3): the user id and the
// role are complete arguments, never a dialogue. `user deactivate` is
// destructive (deactivate-never-delete, ADR-014), so it requires the explicit
// --yes confirmation flag — the CLI never prompts for one. The acting identity
// is selected with --as; it defaults to the configured auth.bypass_principal.

package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// userCommandTimeout bounds one user-administration command: a read plus at
// most one guarded transaction.
const userCommandTimeout = 30 * time.Second

// userSubcommands lists the supported subcommands for the error message.
const userSubcommands = "list, grant, revoke, deactivate"

// runUser dispatches `risksignal user <subcommand>`.
func runUser(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.emit("user", e.fail(exitValidation, classValidation, "missing subcommand (supported: %s)", userSubcommands))
	}
	command := "user " + args[0]
	switch args[0] {
	case "list":
		return e.emit(command, e.cmdUserList(args[1:]))
	case "grant":
		return e.emit(command, e.cmdUserRole("grant", args[1:]))
	case "revoke":
		return e.emit(command, e.cmdUserRole("revoke", args[1:]))
	case "deactivate":
		return e.emit(command, e.cmdUserDeactivate(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation, "unknown subcommand (supported: %s)", userSubcommands))
	}
}

// cmdUserList runs `risksignal user list [--limit <n>] [--cursor <c>]
// [--as <subject>]`: the cursor-paginated user list with each user's roles.
func (e *cmdEnv) cmdUserList(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal user list [--limit <n>] [--cursor <c>] [--as <subject>]")
	limit := fs.Int("limit", 0, "page size (default 20, max 100)")
	cursor := fs.String("cursor", "", "opaque page cursor from a previous page")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if *limit < 0 {
		return e.fail(exitValidation, classValidation, "--limit must be >= 0")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), userCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveUserActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}
	page, err := svc.ListUsers(ctx, application.ListUsersInput{Limit: *limit, Cursor: *cursor, Actor: actor})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	result := userListResult{Data: userViews(page.Users), NextCursor: page.NextCursor}
	if e.format == formatText {
		printUserList(e.stdout, result)
	}
	return e.ok(result)
}

// cmdUserRole runs `risksignal user grant|revoke --user <id> --role <role>
// [--as <subject>]`.
func (e *cmdEnv) cmdUserRole(verb string, args []string) outcome {
	fs := newFlagSet(e, fmt.Sprintf("usage: risksignal user %s --user <id> --role <role> [--as <subject>]", verb))
	user := fs.String("user", "", "internal user id (mandatory)")
	role := fs.String("role", "", "role: security_analyst, system_responsible, administrator, auditor, product_owner (mandatory)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*user) == "" {
		return e.fail(exitValidation, classValidation, "--user is mandatory (the internal user id)")
	}
	r := domain.Role(strings.TrimSpace(*role))
	if !r.Valid() {
		return e.fail(exitValidation, classValidation, "invalid role %q (security_analyst, system_responsible, administrator, auditor, product_owner)", *role)
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), userCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveUserActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}
	var (
		userRec application.UserRecord
		err     error
	)
	if verb == "grant" {
		userRec, err = svc.GrantRole(ctx, application.GrantRoleInput{UserID: *user, Role: r, Actor: actor})
	} else {
		userRec, err = svc.RevokeRole(ctx, application.RevokeRoleInput{UserID: *user, Role: r, Actor: actor})
	}
	if err != nil {
		return applicationErrorOutcome(err)
	}
	view := userViewOf(userRec)
	if e.format == formatText {
		printUserChanged(e.stdout, verb, view)
	}
	return e.ok(view)
}

// cmdUserDeactivate runs `risksignal user deactivate --user <id> --yes
// [--as <subject>]`: the destructive deactivate-never-delete command
// (ADR-014); without --yes it is a validation failure, never a prompt.
func (e *cmdEnv) cmdUserDeactivate(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal user deactivate --user <id> --yes [--as <subject>]")
	user := fs.String("user", "", "internal user id (mandatory)")
	yes := fs.Bool("yes", false, "confirm the destructive deactivation (mandatory)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*user) == "" {
		return e.fail(exitValidation, classValidation, "--user is mandatory (the internal user id)")
	}
	if !*yes {
		return e.fail(exitValidation, classValidation, "user deactivate is destructive; pass --yes to confirm (the CLI never prompts)")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), userCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveUserActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}
	userRec, err := svc.DeactivateUser(ctx, application.DeactivateUserInput{UserID: *user, Actor: actor})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	view := userViewOf(userRec)
	if e.format == formatText {
		printUserChanged(e.stdout, "deactivate", view)
	}
	return e.ok(view)
}

// resolveUserActor resolves the acting identity (the --as subject or the
// configured bypass principal) into the audit actor.
func (e *cmdEnv) resolveUserActor(ctx context.Context, svc *application.Service, cfg *config.Config, as string) (application.Actor, outcome) {
	actor, err := svc.ResolveActor(ctx, domain.Identity{SubjectID: signalSubject(cfg, as)})
	if err != nil {
		return application.Actor{}, applicationErrorOutcome(err)
	}
	return actor, outcome{}
}

// userListResult is the machine-readable payload of a user list page
// (mirrors the API UserList).
type userListResult struct {
	Data       []userView `json:"data"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// userView is the machine-readable user view (the API User schema, snake_case,
// stable keys; zero timestamps render as null, an empty email as null).
type userView struct {
	ID            string     `json:"id"`
	SubjectID     string     `json:"subject_id"`
	DisplayName   string     `json:"display_name"`
	Email         *string    `json:"email"`
	Roles         []string   `json:"roles"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

// userViews maps a page of user records.
func userViews(users []application.UserRecord) []userView {
	out := make([]userView, 0, len(users))
	for _, u := range users {
		out = append(out, userViewOf(u))
	}
	return out
}

// userViewOf maps one user record onto the wire shape.
func userViewOf(u application.UserRecord) userView {
	roles := make([]string, 0, len(u.Roles))
	for _, r := range u.Roles {
		roles = append(roles, string(r))
	}
	var email *string
	if u.Email != "" {
		e := u.Email
		email = &e
	}
	var deactivatedAt, lastLoginAt *time.Time
	if !u.DeactivatedAt.IsZero() {
		d := u.DeactivatedAt
		deactivatedAt = &d
	}
	if !u.LastLoginAt.IsZero() {
		l := u.LastLoginAt
		lastLoginAt = &l
	}
	return userView{
		ID:            u.ID,
		SubjectID:     u.SubjectID,
		DisplayName:   u.DisplayName,
		Email:         email,
		Roles:         roles,
		DeactivatedAt: deactivatedAt,
		LastLoginAt:   lastLoginAt,
		CreatedAt:     u.CreatedAt,
	}
}

// printUserList renders one page of the user list.
func printUserList(w io.Writer, r userListResult) {
	fmt.Fprintf(w, "%d user(s):\n", len(r.Data))
	for _, u := range r.Data {
		state := "active"
		if u.DeactivatedAt != nil {
			state = "deactivated"
		}
		fmt.Fprintf(w, "  %s %s [%s] roles=%s\n", u.ID, u.DisplayName, state, strings.Join(u.Roles, ","))
	}
	if r.NextCursor != "" {
		fmt.Fprintf(w, "next_cursor: %s\n", r.NextCursor)
	}
}

// printUserChanged renders the outcome of a role change / deactivation.
func printUserChanged(w io.Writer, verb string, u userView) {
	fmt.Fprintf(w, "user %s: %s applied — display name %q, roles %s\n",
		u.ID, verb, u.DisplayName, strings.Join(u.Roles, ","))
}
