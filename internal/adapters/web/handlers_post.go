// POST handlers of the web adapter (ARCH-006 §3.1/§3.2). Each parses the form,
// validates the per-session CSRF token (and, for destructive actions, the
// confirmation token), translates onto the matching application input and
// re-renders the affected view with the same error semantics as the API.
package web

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// guard runs the shared pre-dispatch checks of every POST: parse the form,
// resolve the principal, validate the CSRF token. It returns ok=false after it
// has already answered the request.
func (w *Web) guard(rw http.ResponseWriter, r *http.Request) (principalView, application.Actor, bool) {
	// Bounded by the middleware chain's LimitBodyFor(MaxBodyBytes) wrapper.
	if err := r.ParseForm(); err != nil { //nolint:gosec // request body is capped by the chain
		w.renderErrorPage(rw, r, http.StatusBadRequest, "malformed form submission")
		return principalView{}, application.Actor{}, false
	}
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return principalView{}, application.Actor{}, false
	}
	if !w.csrfValid(r) {
		w.renderErrorPage(rw, r, http.StatusForbidden, "CSRF token missing or invalid — reload the page and retry")
		return principalView{}, application.Actor{}, false
	}
	return pv, actor, true
}

// expectedVersion parses the optimistic-lock version of a form.
func expectedVersion(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.PostFormValue("expected_version"))
	if raw == "" {
		return 0, errors.New("expected_version is required")
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("expected_version is not a number")
	}
	return v, nil
}

// handleAcknowledge handles POST /signals/{id}/acknowledge.
func (w *Web) handleAcknowledge(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	ver, err := expectedVersion(r)
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.AcknowledgeSignal(r.Context(), application.AcknowledgeSignalInput{
		SignalID: id, ExpectedVersion: ver, Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "Signal acknowledged."}, "")
}

// handleTransition handles POST /signals/{id}/transition. Entering a closed
// state is destructive and requires the confirmation token (ARCH-006 §4 row 3).
func (w *Web) handleTransition(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	to, err := domain.ParseSignalStatus(r.PostFormValue("status"))
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if to.IsClosed() && !confirmValid(r, "transition", id) {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id,
			&flashMessage{Kind: "error", Message: "This transition changes the signal to a closed state; the confirmation token is missing."}, "")
		return
	}
	ver, err := expectedVersion(r)
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.TransitionSignal(r.Context(), application.TransitionSignalInput{
		SignalID: id, To: to, Reason: r.PostFormValue("reason"), ExpectedVersion: ver, Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "Signal transitioned."}, "")
}

// handleAssign handles POST /signals/{id}/assign.
func (w *Web) handleAssign(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	ver, err := expectedVersion(r)
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.AssignOwner(r.Context(), application.AssignOwnerInput{
		SignalID: id, Owner: strings.TrimSpace(r.PostFormValue("owner_id")), ExpectedVersion: ver, Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "Owner updated."}, "")
}

// handleComment handles POST /signals/{id}/comment.
func (w *Web) handleComment(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, err := w.svc.AddComment(r.Context(), application.AddCommentInput{
		SignalID: id, Body: r.PostFormValue("comment"), Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "Comment added."}, "")
}

// handleOverride handles POST /signals/{id}/override (destructive).
func (w *Web) handleOverride(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !confirmValid(r, "override", id) {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id,
			&flashMessage{Kind: "error", Message: "Priority override requires the confirmation token."}, "")
		return
	}
	prio, err := domain.ParsePriority(r.PostFormValue("priority"))
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	ver, err := expectedVersion(r)
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.OverridePriority(r.Context(), application.OverridePriorityInput{
		SignalID: id, Priority: prio, Reason: r.PostFormValue("reason"), ExpectedVersion: ver, Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "Priority overridden."}, "")
}

// handleRevert handles POST /signals/{id}/revert (destructive).
func (w *Web) handleRevert(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !confirmValid(r, "revert", id) {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id,
			&flashMessage{Kind: "error", Message: "Reverting a priority override requires the confirmation token."}, "")
		return
	}
	ver, err := expectedVersion(r)
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.RevertPriority(r.Context(), application.RevertPriorityInput{
		SignalID: id, ExpectedVersion: ver, Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "Priority override reverted."}, "")
}

// handlePauseSLA handles POST /signals/{id}/pause-sla (destructive).
func (w *Web) handlePauseSLA(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !confirmValid(r, "pause-sla", id) {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id,
			&flashMessage{Kind: "error", Message: "Pausing an SLA clock requires the confirmation token."}, "")
		return
	}
	target, err := domain.ParseSLATarget(r.PostFormValue("target"))
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.PauseSla(r.Context(), application.PauseSlaInput{
		SignalID: id, Target: target, Reason: r.PostFormValue("reason"), Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "SLA clock paused."}, "")
}

// handleResumeSLA handles POST /signals/{id}/resume-sla.
func (w *Web) handleResumeSLA(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	target, err := domain.ParseSLATarget(r.PostFormValue("target"))
	if err != nil {
		w.renderSignalDetail(rw, r, http.StatusBadRequest, pv, actor, id, &flashMessage{Kind: "error", Message: err.Error()}, "")
		return
	}
	if _, err := w.svc.ResumeSla(r.Context(), application.ResumeSlaInput{
		SignalID: id, Target: target, Reason: r.PostFormValue("reason"), Actor: actor, CorrelationID: correlationID(r),
	}); err != nil {
		w.renderSignalCommandError(rw, r, pv, actor, id, err)
		return
	}
	w.renderSignalDetail(rw, r, http.StatusOK, pv, actor, id, &flashMessage{Kind: "success", Message: "SLA clock resumed."}, "")
}

// renderSignalCommandError maps a signal-command error: a stale expected_version
// (conflict) re-renders the detail with a visible notice and the fresh version
// at HTTP 409; other classes re-render or answer the error page.
func (w *Web) renderSignalCommandError(rw http.ResponseWriter, r *http.Request, pv principalView, actor application.Actor, id string, err error) {
	status := statusForError(err)
	if status == http.StatusConflict {
		w.renderSignalDetail(rw, r, http.StatusConflict, pv, actor, id,
			&flashMessage{Kind: "error", Message: "This signal changed since the form was loaded."},
			"The signal was changed by another user.")
		return
	}
	if status == http.StatusBadRequest || status == http.StatusForbidden || status == http.StatusNotFound {
		w.renderSignalDetail(rw, r, status, pv, actor, id, &flashMessage{Kind: "error", Message: errorMessage(err)}, "")
		return
	}
	w.renderErrorPage(rw, r, status, errorMessage(err))
}

// handleStageImport handles POST /inventory/imports (multipart upload).
func (w *Web) handleStageImport(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(application.InventoryMaxBytes); err != nil { //nolint:gosec // bounded by InventoryMaxBytes
		w.renderErrorPage(rw, r, http.StatusBadRequest, "malformed upload")
		return
	}
	pv, actor, err := w.principalFor(r)
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	if !w.csrfValid(r) {
		w.renderErrorPage(rw, r, http.StatusForbidden, "CSRF token missing or invalid")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		w.renderErrorPage(rw, r, http.StatusBadRequest, "a CSV file is required")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := readAllBounded(file, application.InventoryMaxBytes)
	if err != nil {
		w.renderErrorPage(rw, r, http.StatusBadRequest, err.Error())
		return
	}
	imp, err := w.svc.StageInventoryImport(r.Context(), application.StageInventoryImportInput{
		File: data, Actor: actor, CorrelationID: correlationID(r),
	})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	w.renderImportPage(rw, r, http.StatusOK, pv, actor, &flashMessage{Kind: "success", Message: "Import staged."}, &imp)
}

// handleCommitImport handles POST /inventory/imports/{id}/commit (destructive).
func (w *Web) handleCommitImport(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !confirmValid(r, "inventory-commit", id) {
		w.renderImportPage(rw, r, http.StatusBadRequest, pv, actor,
			&flashMessage{Kind: "error", Message: "Committing an import writes the inventory; the confirmation token is missing."}, nil)
		return
	}
	imp, err := w.svc.CommitStagedInventory(r.Context(), application.CommitStagedInventoryInput{ID: id, Actor: actor})
	if err != nil {
		if statusForError(err) == http.StatusConflict {
			w.renderImportPage(rw, r, http.StatusConflict, pv, actor, &flashMessage{Kind: "error", Message: "Import changed since it was staged."}, nil)
			return
		}
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	w.renderImportPage(rw, r, http.StatusOK, pv, actor, &flashMessage{Kind: "success", Message: "Import committed."}, &imp)
}

// handleGrantRole handles POST /admin/users/{id}/roles/grant.
func (w *Web) handleGrantRole(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	role, err := domain.ParseRole(r.PostFormValue("role"))
	if err != nil {
		w.renderAdminUsers(rw, r, http.StatusBadRequest, pv, actor, &flashMessage{Kind: "error", Message: err.Error()})
		return
	}
	if _, err := w.svc.GrantRole(r.Context(), application.GrantRoleInput{UserID: id, Role: role, Actor: actor, CorrelationID: correlationID(r)}); err != nil {
		w.renderAdminUsers(rw, r, statusForError(err), pv, actor, &flashMessage{Kind: "error", Message: errorMessage(err)})
		return
	}
	w.renderAdminUsers(rw, r, http.StatusOK, pv, actor, &flashMessage{Kind: "success", Message: "Role granted."})
}

// handleRevokeRole handles POST /admin/users/{id}/roles/revoke (destructive).
func (w *Web) handleRevokeRole(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !confirmValid(r, "role-revoke", id) {
		w.renderAdminUsers(rw, r, http.StatusBadRequest, pv, actor,
			&flashMessage{Kind: "error", Message: "Revoking a role requires the confirmation token."})
		return
	}
	role, err := domain.ParseRole(r.PostFormValue("role"))
	if err != nil {
		w.renderAdminUsers(rw, r, http.StatusBadRequest, pv, actor, &flashMessage{Kind: "error", Message: err.Error()})
		return
	}
	if _, err := w.svc.RevokeRole(r.Context(), application.RevokeRoleInput{UserID: id, Role: role, Actor: actor, CorrelationID: correlationID(r)}); err != nil {
		w.renderAdminUsers(rw, r, statusForError(err), pv, actor, &flashMessage{Kind: "error", Message: errorMessage(err)})
		return
	}
	w.renderAdminUsers(rw, r, http.StatusOK, pv, actor, &flashMessage{Kind: "success", Message: "Role revoked."})
}

// handleDeactivateUser handles POST /admin/users/{id}/deactivate (destructive).
func (w *Web) handleDeactivateUser(rw http.ResponseWriter, r *http.Request) {
	pv, actor, ok := w.guard(rw, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !confirmValid(r, "deactivate", id) {
		w.renderAdminUsers(rw, r, http.StatusBadRequest, pv, actor,
			&flashMessage{Kind: "error", Message: "Deactivating a user requires the confirmation token."})
		return
	}
	if _, err := w.svc.DeactivateUser(r.Context(), application.DeactivateUserInput{UserID: id, Actor: actor, CorrelationID: correlationID(r)}); err != nil {
		w.renderAdminUsers(rw, r, statusForError(err), pv, actor, &flashMessage{Kind: "error", Message: errorMessage(err)})
		return
	}
	w.renderAdminUsers(rw, r, http.StatusOK, pv, actor, &flashMessage{Kind: "success", Message: "User deactivated."})
}

// renderAdminUsers re-renders the user-admin page at a status with a flash.
func (w *Web) renderAdminUsers(rw http.ResponseWriter, r *http.Request, status int, pv principalView, actor application.Actor, flash *flashMessage) {
	csrf := w.csrfToken(rw, r)
	page, err := w.svc.ListUsers(r.Context(), application.ListUsersInput{Limit: 50, Actor: actor})
	if err != nil {
		w.renderErrorPage(rw, r, statusForError(err), errorMessage(err))
		return
	}
	rows := make([]userRow, 0, len(page.Users))
	for _, u := range page.Users {
		active := u.DeactivatedAt.IsZero()
		state := "active"
		if !active {
			state = "deactivated"
		}
		rows = append(rows, userRow{
			ID: u.ID, DisplayName: u.DisplayName, Email: u.Email, Roles: u.Roles,
			Active: active, StateLabel: state,
			ConfirmRevoke: confirmToken("role-revoke", u.ID), ConfirmDeactivate: confirmToken("deactivate", u.ID),
		})
	}
	w.renderPage(rw, status, "admin-users", adminUsersView{
		chrome: w.newChrome("Users", "/admin/users", pv, flash, csrf),
		Users:  rows, Roles: roleOptions(),
	})
}

// renderImportPage re-renders the inventory-import page, optionally with a
// staged record.
func (w *Web) renderImportPage(rw http.ResponseWriter, r *http.Request, status int, pv principalView, actor application.Actor, flash *flashMessage, imp *application.InventoryImport) {
	csrf := w.csrfToken(rw, r)
	view := inventoryImportView{chrome: w.newChrome("Inventory import", "/inventory/imports", pv, flash, csrf)}
	if imp != nil {
		view.Import = toImportView(*imp)
		view.ConfirmCommit = confirmToken("inventory-commit", imp.ID)
	}
	w.renderPage(rw, status, "inventory-import", view)
}

// correlationID returns the request correlation id (set by the chain) to link
// the audit/outbox rows, or "".
func correlationID(r *http.Request) string {
	return r.Header.Get("X-Correlation-ID")
}

// readAllBounded reads at most max bytes, rejecting an oversized stream.
func readAllBounded(rc io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("upload exceeds the inventory limit")
	}
	return data, nil
}
