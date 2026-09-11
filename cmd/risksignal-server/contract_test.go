package main

// Contract test of the I1b signal API (WP-1b.09 / DEV-023, ADR-011 gate 3,
// ARCH-001 §4): the generated client — the only client of the wire contract
// — is driven against the real server stack, seeded through the real
// `demo seed` CLI path (WP-1b.05).
//
// The stack is fully real, end to end:
//   - a fresh, short-lived PostgreSQL (newServerTestDB) is migrated with the
//     embedded migration set;
//   - the risksignal CLI binary is built once and `demo seed` runs against
//     that database — the WP-1b.05 operator path that produces the
//     deterministic reference signals (C1–C4: P1, P2, P2, P3);
//   - the real composition root of this package (newHandler) serves the
//     seeded database over httptest, behind the full WP-1a.06 middleware
//     chain;
//   - the generated client (gen.NewClientWithResponses, emitted from the
//     same OpenAPI document by oapi-codegen, DEV-021/DEV-023) makes the
//     requests.
//
// The suite pins the contract as the document declares it: the
// {data, next_cursor} page envelope with the ARCH-001 §4 sort, the single
// Signal, cursor pagination, and the RFC 9457 problem details of the
// declared 400/404/500 responses — required fields {type, title, status,
// correlation_id} always present, correlation_id echoing the request id.
// The OpenAPI document itself is first validated against the 3.1
// specification (ADR-011 gate 1) and the declared responses are checked
// against the contract statements of this work package, so the suite stands
// alone. In CI the same kin-openapi validation runs standalone as the lint
// job's gate 1 (TestOpenAPIDocumentValidatesAgainst31 below — the no-Node
// equivalent of the redocly `make validate-openapi` gate, which stays a
// local developer check), and the generate diff-gate runs in that same job
// (`make lint-openapi-diff`, WP-1b.11).
//
// Like the other composition-root integration tests, the suite skips when
// no PostgreSQL is reachable, so `go test ./...` and `make ci-test` stay
// green on machines without the compose environment.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
)

// openapiDocPath is the contract document, relative to this package's
// directory (go test runs with the package directory as working directory).
const openapiDocPath = "../../api/openapi/openapi.yaml"

// knownSignalCVEs is the deterministic outcome of one `demo seed`: the
// WP-1b.05 reference cases C1–C4 of ARCH-001 §3 plus the WP-4.08 / DEV-083 I4
// fixture (ARCH-004 §8), in the sort order of the working-list read —
// priority ascending P1→P4, then created_at, then id. Within a priority the
// fixture signals are created three minutes before the synthetic run, so
// they sort first, ordered by their fixed ids; the synthetic P2 pair
// (C2, C3) is ordered by created_at, which the seed produces in case order.
var knownSignalCVEs = []string{
	"CVE-2026-9001", "CVE-2026-9002", // P1 fixture
	"CVE-2024-0001",                  // P1 synthetic C1
	"CVE-2026-9003", "CVE-2026-9004", // P2 fixture
	"CVE-2024-0002", "CVE-2024-0003", // P2 synthetic C2, C3
	"CVE-2026-9005", "CVE-2026-9006", // P3 fixture
	"CVE-2024-0004",                  // P3 synthetic C4
	"CVE-2026-9007", "CVE-2026-9008", // P4 fixture
}

var knownSignalPriorities = []gen.Priority{
	gen.P1, gen.P1, gen.P1,
	gen.P2, gen.P2, gen.P2, gen.P2,
	gen.P3, gen.P3, gen.P3,
	gen.P4, gen.P4,
}

// TestSignalContractAgainstSeededServer is the ADR-011 gate 3 contract
// suite. One seeded server serves every subtest — the seed is the expensive
// step (a fresh database, migrations and one demo seed); the subtests share
// it and only read. The internal-error subtest runs last: it breaks the
// database on purpose (drops risk_signals) to prove the declared 500.
func TestSignalContractAgainstSeededServer(t *testing.T) {
	t.Parallel() // needs only its own scratch database
	dbURL := newServerTestDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Migrate the fresh database with the real embedded migration set
	// (the same wiring the composition roots use).
	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		_ = runner.Close()
		t.Fatalf("migrate fresh database: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	// Seed through the real CLI path: `demo seed` (WP-1b.05) against this
	// database, exactly as an operator would run it.
	seedDemo(t, dbURL)

	pool, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	// The real composition root behind httptest.
	handler, err := newHandler(testConfig(dbURL), pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := gen.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("gen.NewClientWithResponses: %v", err)
	}

	t.Run("document validates against openapi 3.1 and declares the contract", func(t *testing.T) {
		validateOpenAPIContract(t)
	})

	// The listSignals 200 contract: the {data, next_cursor} envelope in the
	// ARCH-001 §4 sort, with every required Signal field present.
	var listPage *gen.SignalList
	t.Run("listSignals returns the sorted envelope", func(t *testing.T) {
		resp, err := client.ListSignalsWithResponse(ctx, &gen.ListSignalsParams{}, withRequestID(t, "contract-list-1"))
		if err != nil {
			t.Fatalf("ListSignalsWithResponse: %v", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode(), resp.Body)
		}
		if resp.JSON200 == nil {
			t.Fatalf("JSON200 = nil; body: %s", resp.Body)
		}
		if got := resp.HTTPResponse.Header.Get("X-Request-ID"); got != "contract-list-1" {
			t.Errorf("X-Request-ID echo = %q, want %q", got, "contract-list-1")
		}
		page := resp.JSON200
		listPage = page
		if page.Data == nil {
			t.Fatalf("data = null, want the [] array of the schema")
		}
		if len(page.Data) != len(knownSignalCVEs) {
			t.Fatalf("data has %d signals, want %d (one demo seed produces %v)",
				len(page.Data), len(knownSignalCVEs), knownSignalCVEs)
		}
		if page.NextCursor != nil {
			t.Errorf("next_cursor = %q, want null on the single default-size page", *page.NextCursor)
		}
		// Sort: priority ascending P1→P4, then created_at (ch. 10.4); the
		// list holds exactly the deterministic seed rows.
		for i, s := range page.Data {
			if s.CveId != knownSignalCVEs[i] {
				t.Errorf("data[%d].cve_id = %q, want %q (sort order)", i, s.CveId, knownSignalCVEs[i])
			}
			if s.Priority != knownSignalPriorities[i] {
				t.Errorf("data[%d].priority = %s, want %s", i, s.Priority, knownSignalPriorities[i])
			}
			if i > 0 && page.Data[i-1].Priority == page.Data[i].Priority &&
				page.Data[i-1].CreatedAt.After(page.Data[i].CreatedAt) {
				t.Errorf("created_at tiebreak out of order at %d", i)
			}
		}
		// Every Signal on the wire carries its required fields (ARCH-001 §4
		// Signal schema), so the contract test pins the full read shape.
		for i := range page.Data {
			assertSignalComplete(t, "listSignals data["+fmt.Sprint(i)+"]", &page.Data[i])
		}
	})

	// getSignal 200: the detail read returns the identical signal.
	t.Run("getSignal returns the detail read", func(t *testing.T) {
		if listPage == nil {
			t.Fatal("listSignals subtest did not run (no page to read from)")
		}
		id := listPage.Data[0].Id
		resp, err := client.GetSignalWithResponse(ctx, id, withRequestID(t, "contract-get-1"))
		if err != nil {
			t.Fatalf("GetSignalWithResponse(%s): %v", id, err)
		}
		if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
			t.Fatalf("status = %d, JSON200 = %v; body: %s", resp.StatusCode(), resp.JSON200, resp.Body)
		}
		sig := resp.JSON200
		assertSignalComplete(t, "getSignal", sig)
		if sig.Id != id || sig.CveId != listPage.Data[0].CveId || sig.Summary != listPage.Data[0].Summary {
			t.Errorf("getSignal = (%s, %s, %q), want the listSignals row (%s, %s, %q)",
				sig.Id, sig.CveId, sig.Summary, id, listPage.Data[0].CveId, listPage.Data[0].Summary)
		}
	})

	// getSignal 404: an unknown but well-formed id answers the declared 404
	// ProblemDetails, correlation id included.
	t.Run("getSignal unknown id renders 404 problem details", func(t *testing.T) {
		const unknown = "00000000-0000-0000-0000-00000000c0de"
		resp, err := client.GetSignalWithResponse(ctx, unknown, withRequestID(t, "contract-404-1"))
		if err != nil {
			t.Fatalf("GetSignalWithResponse(%s): %v", unknown, err)
		}
		if resp.StatusCode() != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %s)", resp.StatusCode(), resp.Body)
		}
		assertProblemDetails(t, "getSignal 404", resp.JSON404, http.StatusNotFound, "Signal not found", "contract-404-1")
		if resp.JSON404.Detail == nil || !strings.Contains(*resp.JSON404.Detail, unknown) {
			t.Errorf("detail = %v, want it to name the unknown signal id", resp.JSON404.Detail)
		}
		if resp.JSON404.Instance == nil || *resp.JSON404.Instance != "/api/v1/signals/"+unknown {
			t.Errorf("instance = %v, want the request path", resp.JSON404.Instance)
		}
	})

	// The declared 400s: invalid enum filter, limit beyond the cap, a query
	// value the binding cannot parse, and a malformed signal id.
	t.Run("invalid priority renders 400 problem details", func(t *testing.T) {
		resp, err := client.ListSignalsWithResponse(ctx, &gen.ListSignalsParams{
			Priority: ptrTo(gen.Priority("P9")),
		}, withRequestID(t, "contract-400-priority"))
		if err != nil {
			t.Fatalf("ListSignalsWithResponse: %v", err)
		}
		if resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode(), resp.Body)
		}
		assertProblemDetails(t, "listSignals invalid priority", resp.JSON400, http.StatusBadRequest, "Invalid request", "contract-400-priority")
		if resp.JSON400.Detail == nil || !strings.Contains(*resp.JSON400.Detail, "P9") {
			t.Errorf("detail = %v, want it to name the invalid priority", resp.JSON400.Detail)
		}
	})

	t.Run("limit beyond the cap renders 400 problem details", func(t *testing.T) {
		resp, err := client.ListSignalsWithResponse(ctx, &gen.ListSignalsParams{Limit: ptrTo(101)}, withRequestID(t, "contract-400-limit"))
		if err != nil {
			t.Fatalf("ListSignalsWithResponse: %v", err)
		}
		if resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode(), resp.Body)
		}
		assertProblemDetails(t, "listSignals limit 101", resp.JSON400, http.StatusBadRequest, "Invalid request", "contract-400-limit")
		if resp.JSON400.Detail == nil || !strings.Contains(*resp.JSON400.Detail, "limit 101") {
			t.Errorf("detail = %v, want it to name the offending limit", resp.JSON400.Detail)
		}
	})

	t.Run("unparsable query value renders 400 problem details", func(t *testing.T) {
		// The generated client cannot express ?limit=abc through its typed
		// params, so the request is built with the raw client of the same
		// generated contract (gen.Client, still no hand-written URL).
		raw, err := gen.NewClient(srv.URL)
		if err != nil {
			t.Fatalf("gen.NewClient: %v", err)
		}
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		httpResp, err := raw.ListSignals(reqCtx, &gen.ListSignalsParams{}, func(_ context.Context, req *http.Request) error {
			req.URL.RawQuery = "limit=abc"
			req.Header.Set("X-Request-ID", "contract-400-param")
			return nil
		})
		if err != nil {
			t.Fatalf("raw ListSignals: %v", err)
		}
		parsed, err := gen.ParseListSignalsResponse(httpResp)
		if err != nil {
			t.Fatalf("ParseListSignalsResponse: %v", err)
		}
		if parsed.StatusCode() != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", parsed.StatusCode(), parsed.Body)
		}
		assertProblemDetails(t, "listSignals ?limit=abc", parsed.JSON400, http.StatusBadRequest, "Invalid request", "contract-400-param")
		if parsed.JSON400.Detail == nil || !strings.Contains(*parsed.JSON400.Detail, "limit") {
			t.Errorf("detail = %v, want it to name the offending parameter", parsed.JSON400.Detail)
		}
	})

	t.Run("malformed cursor renders 400 problem details", func(t *testing.T) {
		resp, err := client.ListSignalsWithResponse(ctx, &gen.ListSignalsParams{
			Cursor: ptrTo("not-a-valid-cursor"),
		}, withRequestID(t, "contract-400-cursor"))
		if err != nil {
			t.Fatalf("ListSignalsWithResponse: %v", err)
		}
		if resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode(), resp.Body)
		}
		assertProblemDetails(t, "listSignals malformed cursor", resp.JSON400, http.StatusBadRequest, "Invalid request", "contract-400-cursor")
		if resp.JSON400.Detail == nil || !strings.Contains(*resp.JSON400.Detail, "cursor") {
			t.Errorf("detail = %v, want it to name the invalid cursor", resp.JSON400.Detail)
		}
	})

	t.Run("malformed signal id renders 400 problem details", func(t *testing.T) {
		resp, err := client.GetSignalWithResponse(ctx, "not-a-uuid", withRequestID(t, "contract-400-id"))
		if err != nil {
			t.Fatalf("GetSignalWithResponse: %v", err)
		}
		if resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", resp.StatusCode(), resp.Body)
		}
		assertProblemDetails(t, "getSignal malformed id", resp.JSON400, http.StatusBadRequest, "Invalid request", "contract-400-id")
	})

	// Cursor pagination: page through the whole list with limit 2 and
	// reassemble it — the envelope, the opaque cursor and the sort survive
	// the walk. The seed leaves exactly twelve rows (four synthetic C1–C4
	// plus the eight-signal I4 fixture), so the walk takes six full pages
	// (6×2); the last page is final because the use case's limit+1 probe
	// finds no further row (next_cursor null terminates).
	t.Run("cursor pagination walks the whole list", func(t *testing.T) {
		var (
			got        []gen.Signal
			cursor     *string
			pages      int
			wantCursor = true
		)
		for pages = 0; pages < 20 && wantCursor; pages++ {
			resp, err := client.ListSignalsWithResponse(ctx, &gen.ListSignalsParams{
				Limit:  ptrTo(2),
				Cursor: cursor,
			}, withRequestID(t, fmt.Sprintf("contract-page-%d", pages)))
			if err != nil {
				t.Fatalf("page %d: ListSignalsWithResponse: %v", pages, err)
			}
			if resp.StatusCode() != http.StatusOK || resp.JSON200 == nil {
				t.Fatalf("page %d: status = %d, JSON200 = %v; body: %s", pages, resp.StatusCode(), resp.JSON200, resp.Body)
			}
			got = append(got, resp.JSON200.Data...)
			wantCursor = resp.JSON200.NextCursor != nil
			cursor = resp.JSON200.NextCursor
			if len(resp.JSON200.Data) > 2 {
				t.Fatalf("page %d carries %d signals, want at most the requested limit 2", pages, len(resp.JSON200.Data))
			}
			if pages == 0 && len(resp.JSON200.Data) == 0 {
				t.Fatalf("first page is empty, want the seeded signals")
			}
		}
		if pages == 20 {
			t.Fatalf("pagination did not terminate after 20 pages (cursor walk is stuck)")
		}
		if pages != 6 {
			t.Errorf("walk took %d pages, want 6 (6×2 with limit 2 over 12 signals)", pages)
		}
		if wantCursor {
			t.Errorf("last page still carries a next_cursor, want null termination")
		}
		if len(got) != len(knownSignalCVEs) {
			t.Fatalf("walk reassembled %d signals, want %d (no duplicates, none lost)", len(got), len(knownSignalCVEs))
		}
		for i, s := range got {
			if s.CveId != knownSignalCVEs[i] || s.Priority != knownSignalPriorities[i] {
				t.Errorf("walk[%d] = (%s, %s), want (%s, %s) — the stable sort survives pagination",
					i, s.CveId, s.Priority, knownSignalCVEs[i], knownSignalPriorities[i])
			}
		}
	})

	// The declared 500: an unexpected internal error answers the typed
	// ProblemDetails without a detail field, cause to the log only. The
	// seeded database is broken on purpose (risk_signals dropped) — nothing
	// after this subtest reads, so it runs last.
	t.Run("internal error renders 500 problem details", func(t *testing.T) {
		if _, err := pool.Exec(ctx, "DROP TABLE risk_signals CASCADE"); err != nil {
			t.Fatalf("drop risk_signals to force an internal error: %v", err)
		}
		id := "00000000-0000-0000-0000-0000000000a1"
		resp, err := client.GetSignalWithResponse(ctx, id, withRequestID(t, "contract-500-1"))
		if err != nil {
			t.Fatalf("GetSignalWithResponse: %v", err)
		}
		if resp.StatusCode() != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body: %s)", resp.StatusCode(), resp.Body)
		}
		p := assertProblemDetails(t, "getSignal internal error", resp.JSON500, http.StatusInternalServerError, "Internal server error", "contract-500-1")
		if p.Detail != nil {
			t.Errorf("detail = %q, the internal cause must not leak", *p.Detail)
		}
	})
}

// ---------------------------------------------------------------------------
// OpenAPI document validation (ADR-011 gate 1, inside the contract suite)
// ---------------------------------------------------------------------------

// validateOpenAPIContract loads api/openapi/openapi.yaml and validates it
// against the OpenAPI 3.1 specification with kin-openapi (the same library
// the generated code embeds the document with), then asserts the contract
// statements of this work package: every declared response of the two reads
// references the reusable ProblemDetails component with its required
// fields. It runs inside the contract suite (gate 3, self-verifying) and
// standalone as the CI lint job's ADR-011 gate 1 — the no-Node equivalent
// of the redocly `make validate-openapi` gate, which stays the local
// developer validator (WP-1b.11).
func validateOpenAPIContract(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(openapiDocPath)
	if err != nil {
		t.Fatalf("load %s: %v", openapiDocPath, err)
	}
	if err := doc.Validate(ctx); err != nil {
		t.Fatalf("OpenAPI document invalid against the 3.1 specification: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi version = %q, want 3.1.0", doc.OpenAPI)
	}

	problemRef := "#/components/schemas/ProblemDetails"
	for _, tc := range []struct {
		op     string
		path   string
		status string
	}{
		{"listSignals", "/api/v1/signals", "400"},
		{"listSignals", "/api/v1/signals", "500"},
		{"getSignal", "/api/v1/signals/{signal_id}", "400"},
		{"getSignal", "/api/v1/signals/{signal_id}", "404"},
		{"getSignal", "/api/v1/signals/{signal_id}", "500"},
	} {
		opRef := doc.Paths.Value(tc.path).Get
		if opRef == nil {
			t.Fatalf("%s %s: no GET operation in the document", tc.status, tc.path)
		}
		op := opRef
		if op.OperationID != tc.op {
			t.Errorf("%s %s: operationId = %q, want %q", tc.status, tc.path, op.OperationID, tc.op)
		}
		respRef := op.Responses.Value(tc.status)
		if respRef == nil || respRef.Value == nil {
			t.Errorf("%s %s: response %s is not declared", tc.op, tc.path, tc.status)
			continue
		}
		jsonMedia := respRef.Value.Content.Get("application/json")
		if jsonMedia == nil || jsonMedia.Schema == nil {
			t.Errorf("%s %s: response %s has no application/json schema", tc.op, tc.path, tc.status)
			continue
		}
		if ref := jsonMedia.Schema.Ref; ref != problemRef {
			t.Errorf("%s %s: response %s schema ref = %q, want %q", tc.op, tc.path, tc.status, ref, problemRef)
		}
	}

	// The ProblemDetails component carries its required fields, so the
	// generated typed responses and the client assertions above can rely on
	// them (RFC 9457, ARCH-001 §4).
	pd := doc.Components.Schemas["ProblemDetails"]
	if pd == nil || pd.Value == nil {
		t.Fatal("components.schemas.ProblemDetails is missing from the document")
	}
	for _, required := range []string{"type", "title", "status", "correlation_id"} {
		found := false
		for _, r := range pd.Value.Required {
			if r == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ProblemDetails required = %v, missing %q", pd.Value.Required, required)
		}
	}

	// The I5b contract surface (WP-5b.01): the eight-command vocabulary and
	// the inventory/assets/users/roles resources.
	validateI5bContract(t, doc)

	// The I6 contract surface (WP-6.01): the async exports resources and the
	// retention/legal-hold schemas.
	validateI6Contract(t, doc)
}

// i5bCommandRequired is the per-command required-field set of the generalised
// SignalCommandRequest (ARCH-006 §1.2): the five version-guarded commands
// carry expected_version; the three non-guarded ones do not.
var i5bCommandRequired = map[string][]string{
	"acknowledge":       {"expected_version"},
	"change_status":     {"expected_version", "status"},
	"assign_owner":      {"expected_version", "owner_id"},
	"add_comment":       {"comment"},
	"override_priority": {"expected_version", "priority", "reason"},
	"revert_priority":   {"expected_version"},
	"pause_sla":         {"target", "reason"},
	"resume_sla":        {"target", "reason"},
}

// validateI5bContract pins the I5b statements of the document: the
// eight-command discriminated SignalCommandRequest with its per-command
// required fields, the extended SignalCommandResult with its nullable detail
// fields, and the inventory-import, assets and user/role resources with their
// declared responses. It runs inside the contract suite (gate 3) and in the
// standalone gate-1 hook, so `make lint-openapi-validate` exercises it too.
func validateI5bContract(t *testing.T, doc *openapi3.T) {
	t.Helper()
	i5bClientSurface()

	// --- The eight-command vocabulary -----------------------------------
	cmd := doc.Components.Schemas["SignalCommandRequest"]
	if cmd == nil || cmd.Value == nil {
		t.Fatal("components.schemas.SignalCommandRequest is missing from the document")
	}
	commandProp := cmd.Value.Properties["command"]
	if commandProp == nil || commandProp.Value == nil {
		t.Fatal("SignalCommandRequest.command is missing")
	}
	gotCommands := map[string]bool{}
	for _, v := range commandProp.Value.Enum {
		if s, ok := v.(string); ok {
			gotCommands[s] = true
		}
	}
	if len(gotCommands) != len(i5bCommandRequired) {
		t.Errorf("SignalCommandRequest.command enum = %v, want the eight I5b commands", gotCommands)
	}
	for want := range i5bCommandRequired {
		if !gotCommands[want] {
			t.Errorf("SignalCommandRequest.command enum is missing %q", want)
		}
	}
	if !containsString(cmd.Value.Required, "command") {
		t.Errorf("SignalCommandRequest required = %v, want it to include command", cmd.Value.Required)
	}

	// The per-command required fields declared by the if/then conditionals.
	gotRequired := map[string][]string{}
	for _, sub := range cmd.Value.AllOf {
		if sub == nil || sub.Value == nil || sub.Value.If == nil || sub.Value.If.Value == nil || sub.Value.Then == nil || sub.Value.Then.Value == nil {
			continue
		}
		cond := sub.Value.If.Value.Properties["command"]
		if cond == nil || cond.Value == nil {
			continue
		}
		name, _ := cond.Value.Const.(string)
		if name == "" {
			continue
		}
		gotRequired[name] = sub.Value.Then.Value.Required
	}
	for command, want := range i5bCommandRequired {
		got, ok := gotRequired[command]
		if !ok {
			t.Errorf("SignalCommandRequest declares no required fields for command %q", command)
			continue
		}
		if !sameStringSet(got, want) {
			t.Errorf("SignalCommandRequest required for %q = %v, want %v", command, got, want)
		}
	}

	// --- The extended result with its nullable detail fields -------------
	result := doc.Components.Schemas["SignalCommandResult"]
	if result == nil || result.Value == nil {
		t.Fatal("components.schemas.SignalCommandResult is missing from the document")
	}
	for _, field := range []string{"owner_id", "target", "auto_priority"} {
		if !containsString(result.Value.Required, field) {
			t.Errorf("SignalCommandResult required = %v, want it to include the detail field %q", result.Value.Required, field)
		}
		prop := result.Value.Properties[field]
		if prop == nil || prop.Value == nil || !nullableSchema(prop.Value) {
			t.Errorf("SignalCommandResult.%s = %v, want a nullable detail field", field, prop)
		}
	}

	// --- The I5b resources ----------------------------------------------
	for _, tc := range []struct {
		op       string
		method   string
		path     string
		statuses []string
	}{
		{"createInventoryImport", "POST", "/api/v1/inventory/imports", []string{"200", "400", "403", "413", "500"}},
		{"getInventoryImport", "GET", "/api/v1/inventory/imports/{id}", []string{"200", "400", "403", "404", "500"}},
		{"commitInventoryImport", "POST", "/api/v1/inventory/imports/{id}/commit", []string{"200", "400", "403", "404", "409", "500"}},
		{"listAssets", "GET", "/api/v1/assets", []string{"200", "400", "403", "500"}},
		{"getAssetComponents", "GET", "/api/v1/assets/{id}/components", []string{"200", "400", "403", "404", "500"}},
		{"listUsers", "GET", "/api/v1/users", []string{"200", "400", "403", "500"}},
		{"listRoles", "GET", "/api/v1/roles", []string{"200", "403", "500"}},
		{"updateUserRoles", "PATCH", "/api/v1/users/{id}/roles", []string{"200", "400", "403", "404", "409", "500"}},
		{"deactivateUser", "POST", "/api/v1/users/{id}/deactivate", []string{"200", "400", "403", "404", "409", "500"}},
	} {
		pi := doc.Paths.Value(tc.path)
		if pi == nil {
			t.Errorf("%s %s: path not declared", tc.method, tc.path)
			continue
		}
		var operation *openapi3.Operation
		switch tc.method {
		case "GET":
			operation = pi.Get
		case "POST":
			operation = pi.Post
		case "PATCH":
			operation = pi.Patch
		}
		if operation == nil {
			t.Errorf("%s %s: operation not declared", tc.method, tc.path)
			continue
		}
		if operation.OperationID != tc.op {
			t.Errorf("%s %s: operationId = %q, want %q", tc.method, tc.path, operation.OperationID, tc.op)
		}
		for _, status := range tc.statuses {
			respRef := operation.Responses.Value(status)
			if respRef == nil || respRef.Value == nil {
				t.Errorf("%s %s: response %s is not declared", tc.op, tc.path, status)
				continue
			}
			if status == "200" {
				continue
			}
			jsonMedia := respRef.Value.Content.Get("application/json")
			if jsonMedia == nil || jsonMedia.Schema == nil {
				t.Errorf("%s %s: error response %s has no application/json schema", tc.op, tc.path, status)
				continue
			}
			if ref := jsonMedia.Schema.Ref; ref != "#/components/schemas/ProblemDetails" {
				t.Errorf("%s %s: error response %s schema ref = %q, want ProblemDetails", tc.op, tc.path, status, ref)
			}
		}
	}

	for _, name := range []string{
		"InventoryImport", "InventoryImportPreview", "InventoryImportProblem",
		"InventoryImportWarning", "InventoryImportStatus",
		"Asset", "AssetList", "AssetComponents", "Component",
		"AssetType", "Environment", "VersionScheme", "SLATarget",
		"User", "UserList", "Role", "RoleList", "RoleDescriptor",
		"PermissionGrant", "Scope", "UpdateUserRolesRequest",
	} {
		if s := doc.Components.Schemas[name]; s == nil || s.Value == nil {
			t.Errorf("components.schemas.%s is missing from the document", name)
		}
	}
}

// validateI6Contract pins the I6 statements of the document (WP-6.01,
// ARCH-007 §1.1/§1.2/§2.1/§2.2): the three asynchronous export operations
// with their declared responses (the error responses all ProblemDetails), the
// ExportRecord shape with the frozen filter and the generation-stamped fields,
// and the retention/legal-hold request/report schemas the HTTP + CLI adapters
// bind. It runs inside the contract suite (gate 3) and in the standalone
// gate-1 hook (make lint-openapi-validate), and i6ClientSurface pins the
// generated client at compile time (ADR-011: the generated client is the only
// client of the wire contract).
func validateI6Contract(t *testing.T, doc *openapi3.T) {
	t.Helper()
	i6ClientSurface()

	// --- The export resources --------------------------------------------
	for _, tc := range []struct {
		op       string
		method   string
		path     string
		statuses []string
	}{
		{"createExport", "POST", "/api/v1/exports", []string{"200", "400", "403", "500"}},
		{"getExport", "GET", "/api/v1/exports/{id}", []string{"200", "400", "403", "404", "500"}},
		{"downloadExport", "GET", "/api/v1/exports/{id}/download", []string{"200", "400", "403", "404", "410", "500"}},
	} {
		pi := doc.Paths.Value(tc.path)
		if pi == nil {
			t.Errorf("%s %s: path not declared", tc.method, tc.path)
			continue
		}
		var operation *openapi3.Operation
		switch tc.method {
		case "GET":
			operation = pi.Get
		case "POST":
			operation = pi.Post
		}
		if operation == nil {
			t.Errorf("%s %s: operation not declared", tc.method, tc.path)
			continue
		}
		if operation.OperationID != tc.op {
			t.Errorf("%s %s: operationId = %q, want %q", tc.method, tc.path, operation.OperationID, tc.op)
		}
		for _, status := range tc.statuses {
			respRef := operation.Responses.Value(status)
			if respRef == nil || respRef.Value == nil {
				t.Errorf("%s %s: response %s is not declared", tc.op, tc.path, status)
				continue
			}
			if status == "200" {
				continue // 200 carries the resource (or the artifact), asserted below
			}
			jsonMedia := respRef.Value.Content.Get("application/json")
			if jsonMedia == nil || jsonMedia.Schema == nil {
				t.Errorf("%s %s: error response %s has no application/json schema", tc.op, tc.path, status)
				continue
			}
			if ref := jsonMedia.Schema.Ref; ref != "#/components/schemas/ProblemDetails" {
				t.Errorf("%s %s: error response %s schema ref = %q, want ProblemDetails", tc.op, tc.path, status, ref)
			}
		}
	}

	// createExport/getExport 200 carry the ExportRecord; the download 200 is a
	// binary attachment of any media type (the stored format decides the
	// content type), never JSON-encoded.
	for _, tc := range []struct {
		op     string
		method string
		path   string
		ref    string
	}{
		{"createExport", "POST", "/api/v1/exports", "#/components/schemas/ExportRecord"},
		{"getExport", "GET", "/api/v1/exports/{id}", "#/components/schemas/ExportRecord"},
	} {
		op := doc.Paths.Value(tc.path)
		if op == nil {
			continue
		}
		var operation *openapi3.Operation
		if tc.method == "POST" {
			operation = op.Post
		} else {
			operation = op.Get
		}
		if operation == nil {
			continue
		}
		respRef := operation.Responses.Value("200")
		if respRef == nil || respRef.Value == nil {
			t.Errorf("%s %s: response 200 is not declared", tc.op, tc.path)
			continue
		}
		jsonMedia := respRef.Value.Content.Get("application/json")
		if jsonMedia == nil || jsonMedia.Schema == nil {
			t.Errorf("%s %s: response 200 has no application/json schema", tc.op, tc.path)
			continue
		}
		if ref := jsonMedia.Schema.Ref; ref != tc.ref {
			t.Errorf("%s %s: response 200 schema ref = %q, want %q", tc.op, tc.path, ref, tc.ref)
		}
	}
	dl := doc.Paths.Value("/api/v1/exports/{id}/download")
	if dl != nil && dl.Get != nil {
		respRef := dl.Get.Responses.Value("200")
		if respRef == nil || respRef.Value == nil {
			t.Error("downloadExport: response 200 is not declared")
		} else if bin := respRef.Value.Content.Get("*/*"); bin == nil || bin.Schema == nil {
			t.Error("downloadExport: response 200 has no */* schema")
		}
	}

	// --- The export record shape (ARCH-007 §1.2) -------------------------
	record := doc.Components.Schemas["ExportRecord"]
	if record == nil || record.Value == nil {
		t.Fatal("components.schemas.ExportRecord is missing from the document")
	}
	wantRecordRequired := []string{
		"id", "status", "filter", "created_at", "row_count", "size_bytes",
		"checksum", "schema_version", "rule_version", "expires_at",
	}
	if !sameStringSet(record.Value.Required, wantRecordRequired) {
		t.Errorf("ExportRecord required = %v, want %v", record.Value.Required, wantRecordRequired)
	}
	for _, field := range []string{"row_count", "size_bytes", "checksum", "schema_version", "rule_version", "expires_at"} {
		prop := record.Value.Properties[field]
		if prop == nil || prop.Value == nil || !nullableSchema(prop.Value) {
			t.Errorf("ExportRecord.%s = %v, want a nullable generation-stamped field", field, prop)
		}
	}

	create := doc.Components.Schemas["ExportCreateRequest"]
	if create == nil || create.Value == nil {
		t.Fatal("components.schemas.ExportCreateRequest is missing from the document")
	}
	if !sameStringSet(create.Value.Required, []string{"filter", "format"}) {
		t.Errorf("ExportCreateRequest required = %v, want [filter format]", create.Value.Required)
	}
	assertEnum(t, doc, "ExportFormat", []string{"csv", "json"})
	assertEnum(t, doc, "ExportStatus", []string{"pending", "completed", "failed", "expired"})

	// --- The retention + legal-hold schemas (ARCH-007 §2.1/§2.2) ---------
	for _, name := range []string{
		"ExportFilter",
		"RetentionStage", "RetentionRunStatus", "RetentionDryRunReport",
		"RetentionDryRunRequest", "RetentionApproveRequest", "RetentionExecuteRequest",
		"RetentionRun", "RetentionRunList",
		"LegalHold", "LegalHoldList", "LegalHoldCreateRequest", "LegalHoldReleaseRequest",
	} {
		if s := doc.Components.Schemas[name]; s == nil || s.Value == nil {
			t.Errorf("components.schemas.%s is missing from the document", name)
		}
	}
	assertEnum(t, doc, "RetentionStage", []string{"pseudonymise", "delete"})
	assertEnum(t, doc, "RetentionRunStatus", []string{"dry_run", "approved", "executing", "completed", "failed", "rejected"})

	// The dry-run report is counts-only; the approve/release/create bodies
	// carry the mandatory reason and the legal-hold aggregate id.
	for _, tc := range []struct {
		name     string
		required []string
	}{
		{"RetentionDryRunReport", []string{"candidates", "held", "to_pseudonymise", "to_delete"}},
		{"RetentionApproveRequest", []string{"reason"}},
		{"RetentionExecuteRequest", []string{"run_id"}},
		{"LegalHoldCreateRequest", []string{"aggregate_id", "reason"}},
		{"LegalHoldReleaseRequest", []string{"reason"}},
	} {
		s := doc.Components.Schemas[tc.name]
		if s == nil || s.Value == nil {
			continue
		}
		if !sameStringSet(s.Value.Required, tc.required) {
			t.Errorf("%s required = %v, want %v", tc.name, s.Value.Required, tc.required)
		}
	}
}

// assertEnum asserts the named string schema declares exactly want as its
// enum vocabulary.
func assertEnum(t *testing.T, doc *openapi3.T, name string, want []string) {
	t.Helper()
	s := doc.Components.Schemas[name]
	if s == nil || s.Value == nil {
		t.Errorf("components.schemas.%s is missing from the document", name)
		return
	}
	got := make([]string, 0, len(s.Value.Enum))
	for _, v := range s.Value.Enum {
		if str, ok := v.(string); ok {
			got = append(got, str)
		}
	}
	if !sameStringSet(got, want) {
		t.Errorf("%s enum = %v, want %v", name, got, want)
	}
}

// i6ClientSurface pins the generated client of the I6 export resources at
// compile time (ADR-011: the generated client is the only client of the wire
// contract, and a missing operation is a compile error).
func i6ClientSurface() {
	var _ = (*gen.ClientWithResponses).CreateExportWithResponse
	var _ = (*gen.ClientWithResponses).GetExportWithResponse
	var _ = (*gen.ClientWithResponses).DownloadExportWithResponse
}

// nullableSchema reports whether s admits a JSON null: a [T, "null"] type
// union or a oneOf/anyOf carrying a null branch.
func nullableSchema(s *openapi3.Schema) bool {
	if s.Type != nil && s.Type.IncludesNull() {
		return true
	}
	for _, branches := range [][]*openapi3.SchemaRef{s.OneOf, s.AnyOf} {
		for _, b := range branches {
			if b != nil && b.Value != nil && b.Value.Type != nil && b.Value.Type.IncludesNull() {
				return true
			}
		}
	}
	return false
}

// containsString reports whether list holds want.
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// sameStringSet compares two string slices as sets.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// i5bClientSurface pins the generated client of the I5b resources at compile
// time (ADR-011: the generated client is the only client of the wire
// contract, and a missing operation is a compile error).
func i5bClientSurface() {
	var _ = (*gen.ClientWithResponses).CreateInventoryImportWithBodyWithResponse
	var _ = (*gen.ClientWithResponses).GetInventoryImportWithResponse
	var _ = (*gen.ClientWithResponses).CommitInventoryImportWithResponse
	var _ = (*gen.ClientWithResponses).ListAssetsWithResponse
	var _ = (*gen.ClientWithResponses).GetAssetComponentsWithResponse
	var _ = (*gen.ClientWithResponses).ListUsersWithResponse
	var _ = (*gen.ClientWithResponses).ListRolesWithResponse
	var _ = (*gen.ClientWithResponses).UpdateUserRolesWithResponse
	var _ = (*gen.ClientWithResponses).DeactivateUserWithResponse
}

// ---------------------------------------------------------------------------
// Standalone ADR-011 gate-1 hook (WP-1b.11)
// ---------------------------------------------------------------------------

// TestOpenAPIDocumentValidatesAgainst31 is the ADR-011 gate-1 hook of the CI
// lint job (WP-1b.11, DEV-025): the same kin-openapi document validation the
// contract suite embeds, run standalone — no database, no server — so CI can
// execute it in the no-Node lint job as the equivalent of the redocly
// `make validate-openapi` gate (which stays the local developer validator;
// CI installs no Node toolchain). `go test ./...` picks it up like any
// other test; the CI lint job runs it targeted via
// `go test ./cmd/risksignal-server -run '^TestOpenAPIDocumentValidatesAgainst31$' -count=1`
// and `make ci-lint` through lint-openapi-validate.
func TestOpenAPIDocumentValidatesAgainst31(t *testing.T) {
	validateOpenAPIContract(t)
}

// ---------------------------------------------------------------------------
// Seeding through the demo CLI (WP-1b.05)
// ---------------------------------------------------------------------------

// demoSeedBinaryOnce builds the risksignal CLI once per test process; the
// contract test seeds through the real `demo seed` command.
var (
	demoSeedBinaryOnce sync.Once
	demoSeedBinaryPath string
	demoSeedBinaryErr  error
)

func demoSeedBinary(t *testing.T) string {
	t.Helper()
	demoSeedBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "risksignal-contract-bin")
		if err != nil {
			demoSeedBinaryErr = err
			return
		}
		demoSeedBinaryPath = filepath.Join(dir, "risksignal")
		//nolint:gosec // G204: the module path and build flags are constants;
		// only the scratch output path varies (a MkdirTemp dir this test
		// owns). No shell, no user input and no network reach the process.
		cmd := exec.Command("go", "build", "-o", demoSeedBinaryPath, "github.com/brunoxpera/risksignal/cmd/risksignal")
		if out, err := cmd.CombinedOutput(); err != nil {
			demoSeedBinaryErr = fmt.Errorf("build demo CLI: %w (%s)", err, out)
		}
	})
	if demoSeedBinaryErr != nil {
		t.Fatalf("demo CLI unavailable: %v", demoSeedBinaryErr)
	}
	return demoSeedBinaryPath
}

// seedDemo runs `risksignal demo seed --output json` against dbURL and
// asserts the WP-1b.05 outcome: exit 0, envelope ok, the deterministic
// fixture produced its four reference signals.
func seedDemo(t *testing.T, dbURL string) {
	t.Helper()
	bin := demoSeedBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	//nolint:gosec // G204: bin is the demo CLI this test built itself above
	// and the seed command runs a fixed argument list against the scratch
	// database of this test — no shell, no user-controlled input.
	cmd := exec.CommandContext(ctx, bin, "demo", "seed", "--output", "json")
	cmd.Env = cliEnv(dbURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("demo seed failed: %v (output: %s)", err, out)
	}

	var env struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Class   string `json:"class"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode demo seed envelope from %q: %v", out, err)
	}
	if env.Status != "ok" {
		t.Fatalf("demo seed status = %q (class %v, message %v)", env.Status, env.Error.Class, env.Error.Message)
	}
	var result struct {
		Run struct {
			Status   string   `json:"status"`
			Errors   []string `json:"errors"`
			Counters struct {
				Signals int `json:"signals"`
			} `json:"counters"`
		} `json:"run"`
	}
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("decode demo seed result from %q: %v", env.Result, err)
	}
	// The deterministic fixture counts the malformed E1 case as a run error
	// (terminal status failed, one recorded error) without aborting the run:
	// the four reference signals are created (ARCH-001 §3).
	if result.Run.Status != "failed" {
		t.Fatalf("demo seed run status = %q, want failed (E1 counted)", result.Run.Status)
	}
	if len(result.Run.Errors) != 1 {
		t.Fatalf("demo seed run errors = %v, want exactly the one E1 case error", result.Run.Errors)
	}
	// The synthetic run creates exactly the four reference signals (C1–C4);
	// the eight-signal I4 fixture is seeded separately (ARCH-004 §8) and is
	// not part of the run's counters.
	if result.Run.Counters.Signals != 4 {
		t.Fatalf("demo seed run counters = %+v, want 4 synthetic signals", result.Run.Counters)
	}
}

// cliEnv returns the process environment for the demo CLI pointing at
// dbURL, without inheriting RISKSIGNAL_* values from the test environment
// (the CLI reads configuration from the environment; the test must own it).
func cliEnv(dbURL string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RISKSIGNAL_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"RISKSIGNAL_DATABASE_URL="+dbURL,
		"RISKSIGNAL_OIDC_ISSUER=http://127.0.0.1:9000/oidc",
	)
}

// ---------------------------------------------------------------------------
// Contract assertions
// ---------------------------------------------------------------------------

// withRequestID returns a request editor setting the correlation id header
// the server adopts and echoes (httpapi.HeaderRequestID).
func withRequestID(t *testing.T, id string) gen.RequestEditorFn {
	t.Helper()
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set(httpapi.HeaderRequestID, id)
		return nil
	}
}

// assertProblemDetails asserts the RFC 9457 problem detail of a declared
// error response: required fields {type, title, status, correlation_id}
// present, title and status matching, correlation_id echoing the request id.
func assertProblemDetails(t *testing.T, what string, p *gen.ProblemDetails, wantStatus int, wantTitle, wantCorrID string) gen.ProblemDetails {
	t.Helper()
	if p == nil {
		t.Fatalf("%s: problem details = nil (was the response JSON parsed?)", what)
	}
	if p.Type == "" {
		t.Errorf("%s: type = %q, want non-empty (about:blank)", what, p.Type)
	}
	if p.Title != wantTitle {
		t.Errorf("%s: title = %q, want %q", what, p.Title, wantTitle)
	}
	if p.Status != wantStatus {
		t.Errorf("%s: status = %d, want %d", what, p.Status, wantStatus)
	}
	if p.CorrelationId != wantCorrID {
		t.Errorf("%s: correlation_id = %q, want the request id %q", what, p.CorrelationId, wantCorrID)
	}
	return *p
}

// uuidRE matches the canonical uuid text form of the string identifiers
// (concept ch. 7.2; identifiers on the wire are uuid strings).
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// assertSignalComplete asserts every required field of the ARCH-001 §4
// Signal schema is present and populated on the wire: string ids, the
// enums, the joined asset and product, the RFC 3339 UTC created_at and the
// version token. DueAt is null in I1b (the SLA clocks are I4).
func assertSignalComplete(t *testing.T, what string, s *gen.Signal) {
	t.Helper()
	if !uuidRE.MatchString(s.Id) {
		t.Errorf("%s: id = %q, want a uuid string", what, s.Id)
	}
	if !uuidRE.MatchString(s.MatchId) {
		t.Errorf("%s: match_id = %q, want a uuid string", what, s.MatchId)
	}
	if s.CveId == "" || !strings.HasPrefix(s.CveId, "CVE-") {
		t.Errorf("%s: cve_id = %q, want a CVE identifier", what, s.CveId)
	}
	if !s.Priority.Valid() {
		t.Errorf("%s: priority = %q, not in the vocabulary", what, s.Priority)
	}
	if !s.Status.Valid() {
		t.Errorf("%s: status = %q, not in the vocabulary", what, s.Status)
	}
	if !s.Confidence.Valid() {
		t.Errorf("%s: confidence = %q, not in the vocabulary", what, s.Confidence)
	}
	if !s.Method.Valid() {
		t.Errorf("%s: method = %q, not in the vocabulary", what, s.Method)
	}
	if s.Asset == nil {
		t.Errorf("%s: asset = nil, want the joined asset", what)
	} else {
		if !uuidRE.MatchString(s.Asset.Id) || s.Asset.Name == "" || s.Asset.Type == "" {
			t.Errorf("%s: asset = %+v, want id/name/type populated", what, s.Asset)
		}
		if !s.Asset.Criticality.Valid() || !s.Asset.Exposure.Valid() {
			t.Errorf("%s: asset criticality/exposure = (%q, %q), not in the vocabularies",
				what, s.Asset.Criticality, s.Asset.Exposure)
		}
	}
	if s.Product.Vendor == "" || s.Product.Product == "" || s.Product.Version == "" {
		t.Errorf("%s: product = %+v, want vendor/product/version populated", what, s.Product)
	}
	if s.Summary == "" {
		t.Errorf("%s: summary = %q, want non-empty", what, s.Summary)
	}
	if s.CreatedAt.IsZero() || s.CreatedAt.Location() != time.UTC {
		t.Errorf("%s: created_at = %v, want a non-zero RFC 3339 UTC timestamp", what, s.CreatedAt)
	}
	if s.Version < 1 {
		t.Errorf("%s: version = %d, want the optimistic-lock token >= 1", what, s.Version)
	}
	if s.DueAt != nil {
		t.Errorf("%s: due_at = %v, want null (SLA clocks are I4)", what, *s.DueAt)
	}
}

// ptrTo returns a pointer to v — the generated client parameter structs
// carry optional values as pointers.
func ptrTo[T any](v T) *T {
	return &v
}
