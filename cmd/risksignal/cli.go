// CLI dispatch, exit code contract and machine-readable envelope (WP-1a.09,
// concept ch. 11.3). This file holds everything that is common to every
// subcommand: the run entry point, the exit code constants, the outcome
// verdicts, the --output format selection, the JSON envelope and the usage
// text. The subcommand bodies live in maintenance.go and diagnose.go.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xpera/risksignal/internal/platform/config"
)

// Exit codes (concept ch. 11.3, WP-1a.09). 0 is success; every other code
// names one failure class so that automation can branch without parsing
// output. The mapping is documented in README.md and must not drift.
const (
	exitOK             = 0 // success
	exitGeneric        = 1 // generic/unknown runtime failure
	exitValidation     = 2 // unknown command, invalid arguments, invalid configuration
	exitAuthentication = 3 // authentication failed (reserved: OIDC lands in a later iteration)
	exitAuthorisation  = 4 // authorisation denied (reserved: permission checks land later)
	exitConflict       = 5 // state conflict (e.g. an applied migration was modified, ADR-010)
	exitInfrastructure = 6 // infrastructure failure (database host unreachable, ...)
)

// errorClass names the failure class inside the JSON envelope; the fixed
// vocabulary mirrors the exit codes above.
type errorClass string

const (
	classGeneric        errorClass = "generic"
	classValidation     errorClass = "validation"
	classAuthentication errorClass = "authentication"
	classAuthorisation  errorClass = "authorisation"
	classConflict       errorClass = "conflict"
	classInfrastructure errorClass = "infrastructure"
)

// outputFormat selects the rendering of a command result.
type outputFormat int

const (
	formatText outputFormat = iota // human-readable, the default
	formatJSON                     // machine-readable envelope on stdout
)

// envelopeSchemaVersion versions the machine-readable envelope. Bump only
// when the envelope keys change incompatibly; per-command result payloads
// evolve inside the result object with keys documented per command.
const envelopeSchemaVersion = 1

// envelope is the schema-stable JSON document that every command emits on
// stdout with --output json. The keys are fixed: schema_version, command,
// exit_code, status, result, error. On success status is "ok", result holds
// the command payload and error is null; on failure status is "error",
// result is null and error carries the class and message.
type envelope struct {
	SchemaVersion int         `json:"schema_version"`
	Command       string      `json:"command"`
	ExitCode      int         `json:"exit_code"`
	Status        string      `json:"status"`
	Result        any         `json:"result"`
	Error         *errPayload `json:"error"`
}

// errPayload is the fixed error object of the envelope.
type errPayload struct {
	Class   errorClass `json:"class"`
	Message string     `json:"message"`
}

// outcome is the verdict of one command: either a success with a
// machine-readable result payload, or a failure with an exit code, a class
// and a message. Text rendering of successes happens inside the command
// handlers (they write to cmdEnv.stdout when the format is text); failures
// are rendered centrally by cmdEnv.emit.
type outcome struct {
	code    int
	class   errorClass
	message string
	result  any
}

func (o outcome) ok() bool { return o.code == exitOK }

// cmdEnv carries the rendering context of one CLI invocation. Handlers write
// text output only when the format is text; the JSON envelope is emitted
// centrally by emit.
type cmdEnv struct {
	format outputFormat
	stdout io.Writer
	stderr io.Writer
}

// ok builds a success outcome with the machine-readable result payload.
func (e *cmdEnv) ok(result any) outcome { return outcome{code: exitOK, result: result} }

// fail builds a failure outcome for the given exit code and class.
func (e *cmdEnv) fail(code int, class errorClass, format string, args ...any) outcome {
	return outcome{code: code, class: class, message: fmt.Sprintf(format, args...)}
}

// emit renders an outcome and returns the process exit code. In text mode a
// failure message goes to stderr prefixed with the command path; in JSON
// mode the envelope goes to stdout for every outcome (success and failure
// alike), so automation always gets one parseable document.
func (e *cmdEnv) emit(command string, out outcome) int {
	if e.format == formatJSON {
		env := envelope{
			SchemaVersion: envelopeSchemaVersion,
			Command:       command,
			ExitCode:      out.code,
			Status:        "ok",
		}
		if !out.ok() {
			env.Status = "error"
			env.Error = &errPayload{Class: out.class, Message: out.message}
		} else {
			env.Result = out.result
		}
		b, err := json.MarshalIndent(&env, "", "  ")
		if err != nil {
			// Our payloads are plain data; a failure here is a bug, but the
			// CLI must still terminate with a defined code and no panic.
			fmt.Fprintf(e.stderr, "risksignal %s: cannot render json output: %v\n", command, err)
			return exitGeneric
		}
		fmt.Fprintln(e.stdout, string(b))
		return out.code
	}
	if !out.ok() {
		prefix := "risksignal"
		if command != "" {
			prefix += " " + command
		}
		fmt.Fprintf(e.stderr, "%s: %s\n", prefix, out.message)
	}
	return out.code
}

// run is the CLI entry point used by main and by the tests. It parses the
// global --output flag, dispatches the subcommand and returns the process
// exit code without ever calling os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	format, commandArgs, err := parseOutputFlag(args)
	e := &cmdEnv{format: format, stdout: stdout, stderr: stderr}
	if err != nil {
		return e.emit("", e.fail(exitValidation, classValidation, "%v", err))
	}

	if len(commandArgs) == 0 {
		return e.emit("", e.fail(exitValidation, classValidation, "missing command (run 'risksignal help' for usage)"))
	}

	switch commandArgs[0] {
	case "help", "-h", "--help":
		// Help is the one human-oriented exception: it prints usage text
		// regardless of --output and exits 0.
		printUsage(stdout)
		return exitOK
	case "maintenance":
		return runMaintenance(e, commandArgs[1:])
	case "diagnose":
		return runDiagnose(e, commandArgs[1:])
	case "demo":
		return runDemo(e, commandArgs[1:])
	default:
		return e.emit(commandArgs[0], e.fail(exitValidation, classValidation,
			"unknown command (run 'risksignal help' for usage)"))
	}
}

// parseOutputFlag removes the global --output text|json flag (both the
// space-separated and the --output=value form) from args and returns the
// selected format plus the remaining command arguments. The flag may appear
// anywhere; subcommands never see it.
func parseOutputFlag(args []string) (outputFormat, []string, error) {
	format := formatText
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		var value string
		switch {
		case a == "--output":
			if i+1 >= len(args) {
				return 0, nil, errors.New("--output requires a value (text or json)")
			}
			i++
			value = args[i]
		case strings.HasPrefix(a, "--output="):
			value = strings.TrimPrefix(a, "--output=")
		default:
			rest = append(rest, a)
			continue
		}
		f, err := parseOutputFormat(value)
		if err != nil {
			return 0, nil, err
		}
		format = f
	}
	return format, rest, nil
}

// parseOutputFormat validates the value of --output.
func parseOutputFormat(value string) (outputFormat, error) {
	switch value {
	case "text":
		return formatText, nil
	case "json":
		return formatJSON, nil
	default:
		return 0, fmt.Errorf("--output: unsupported format %q (supported: text, json)", value)
	}
}

// newFlagSet builds a subcommand flag set that never prompts and never reads
// a terminal: parse diagnostics are discarded and usage is rendered only as
// text on stderr (usage text is human-oriented and would corrupt a JSON
// envelope). flag.ErrHelp still signals a help request to the caller.
func newFlagSet(e *cmdEnv, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("subcommand", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		if e.format == formatText {
			fmt.Fprintln(e.stderr, usage)
		}
	}
	return fs
}

// loadConfig loads and validates the process configuration (WP-1a.02). A
// failure is a validation outcome (exit code 2): the error references
// configuration keys only, never secret values.
func loadConfig(e *cmdEnv) (*config.Config, outcome) {
	cfg, err := config.Load()
	if err != nil {
		return nil, e.fail(exitValidation, classValidation, "invalid configuration: %v", err)
	}
	return cfg, outcome{}
}

// dialTimeout bounds the TCP probes of the diagnose commands. Loopback
// refuses instantly; the bound keeps automation from hanging on a
// blackholed host.
const dialTimeout = 5 * time.Second

// printUsage renders the top-level CLI usage.
func printUsage(w io.Writer) {
	fmt.Fprint(w, `usage: risksignal <command> [arguments] [--output text|json]

commands:
  maintenance migrate [--dry-run]   apply pending schema migrations
                                    (checksum-guarded, ADR-010)
  maintenance retention             delete expired data (not yet implemented)
  maintenance recompute             recompute derived signals (not yet implemented)
  diagnose config                   print the configuration provenance report
                                    (sources, never secret values)
  diagnose connectivity             probe TCP reachability of the database host
  diagnose health                   report process and database connectivity
  demo seed                         register the synthetic source, seed the
                                    demo inventory and run the source once
                                    (deterministic reference fixture, WP-1b.05)
  demo run                          re-run the synthetic source (idempotent
                                    no-op on re-run)
  demo reset --yes                  truncate the I1b demo tables (dev-only)
  help                              show this help

The CLI is strictly non-interactive: it never prompts and never reads hidden
defaults from a terminal. Destructive maintenance commands require complete
parameters (--yes once implemented), never a terminal dialogue.

exit codes:
  0  success
  1  generic/unknown failure
  2  validation (unknown command, invalid arguments, invalid configuration)
  3  authentication (reserved, OIDC lands in a later iteration)
  4  authorisation (reserved)
  5  conflict (for example an applied migration was modified, ADR-010)
  6  infrastructure (database host unreachable)

output:
  Human-readable text by default. With --output json every command emits one
  machine-readable envelope on stdout with the fixed keys schema_version,
  command, exit_code, status, result, error; the envelope keys never change.
`)
}
