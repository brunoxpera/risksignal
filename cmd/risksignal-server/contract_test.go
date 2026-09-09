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
// alone; the redocly validation of `make validate-openapi` and the
// generate diff-gate run in CI regardless (WP-1b.11).
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

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/httpapi"
	"github.com/xpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

// openapiDocPath is the contract document, relative to this package's
// directory (go test runs with the package directory as working directory).
const openapiDocPath = "../../api/openapi/openapi.yaml"

// knownSignalCVEs is the deterministic outcome of one `demo seed` (the
// WP-1b.05 reference cases C1–C4 of ARCH-001 §3): four signals in the sort
// order of the working-list read — priority ascending P1→P4, then
// created_at. The P2 pair (C2, C3) is ordered by created_at, which the
// seed produces in case order; the suite pins the priority sequence and the
// first element, not the microseconds of the P2 tiebreak.
var knownSignalCVEs = []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"}

var knownSignalPriorities = []gen.Priority{gen.P1, gen.P2, gen.P2, gen.P3}

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
	srv := httptest.NewServer(newHandler(testConfig(dbURL), pool, discardLogger()))
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
	// the walk. The seed leaves exactly four rows, so the walk takes two
	// full pages (2+2); the second page is final because the use case's
	// limit+1 probe finds no further row (next_cursor null terminates).
	t.Run("cursor pagination walks the whole list", func(t *testing.T) {
		var (
			got        []gen.Signal
			cursor     *string
			pages      int
			wantCursor = true
		)
		for pages = 0; pages < 10 && wantCursor; pages++ {
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
		if pages == 10 {
			t.Fatalf("pagination did not terminate after 10 pages (cursor walk is stuck)")
		}
		if pages != 2 {
			t.Errorf("walk took %d pages, want 2 (2+2 with limit 2 over 4 signals)", pages)
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
		if _, err := pool.Exec(ctx, "DROP TABLE risk_signals"); err != nil {
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
// fields. The redocly lint of `make validate-openapi` remains the CI gate-1
// validator; this keeps the contract suite self-verifying.
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
		cmd := exec.Command("go", "build", "-o", demoSeedBinaryPath, "github.com/xpera/risksignal/cmd/risksignal")
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
	if result.Run.Counters.Signals != len(knownSignalCVEs) {
		t.Fatalf("demo seed run counters = %+v, want %d signals", result.Run.Counters, len(knownSignalCVEs))
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
	if !s.Status.Valid() || s.Status != gen.New {
		t.Errorf("%s: status = %q, want %q (I1b signals are always new)", what, s.Status, gen.New)
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
