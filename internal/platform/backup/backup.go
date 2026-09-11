// Package backup implements the I6 encrypted off-host logical backup and the
// repeatable restore test (ARCH-007 §4, NFR-011, AT-015, WP-6.09 / DEV-122).
//
// The backup is the daily logical `pg_dump -Fc` of the whole database,
// encrypted with `age` and written off-host (a separate volume/mount, never
// the runtime host's data directory; ARCH-007 §4 "ausserhalb des
// Laufzeithosts"). The `age` identity is runtime-injected: the configuration
// key backup.encryption_key_ref names the secret (an environment variable),
// never the key itself, and the recipient used for encryption is derived from
// the identity so one referenced secret covers both directions. The encrypted
// off-host artifact is the external tamper-evidence for the audit trail
// (concept ch. 12.4 "externe Backups").
//
// The package is the mechanics only — pg_dump/pg_restore, age, the off-host
// retention and the integrity assertions. The composition root (cmd) drives
// it: it creates the throwaway empty instance, runs the checked migration
// runner (ADR-010) and records the `backup.restored` audit event. Nothing here
// is part of the application process: the production backup is a containerised
// sidecar/cron (see scripts/backup.sh and deploy/backup).
package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// Artifact suffix and prefix of the encrypted backup files. The timestamp is
// UTC and lexically sortable, so the newest artifact is also the
// lexically-largest name (the restore test uses the newest by modification
// time, which the sidecar keeps identical to the name).
const (
	backupPrefix = "risksignal-"
	backupSuffix = ".dump.age"
	backupPerm   = 0o600
	backupDirMu  = 0o700
)

// Settings is the resolved backup configuration. Identity carries the secret
// and is never rendered; KeyRef is the reference name (not the key) and is
// safe to mention in messages.
type Settings struct {
	// Dir is the off-host backup root (backup.dir).
	Dir string
	// RetainDays is the pruning horizon in days (backup.retain_days, ≥14).
	RetainDays int
	// KeyRef names the runtime-injected age identity (backup.encryption_key_ref).
	KeyRef string
	// Identity is the resolved age identity (the secret). It is used to derive
	// the encryption recipient and to decrypt on restore.
	Identity *age.X25519Identity
	// PGDump and PGRestore override the pg_dump/pg_restore executables; empty
	// falls back to PATH. A matching client major version is required (a
	// newer client can dump an older server, never the other way round).
	PGDump    string
	PGRestore string
}

func (s Settings) pgDump() string {
	if strings.TrimSpace(s.PGDump) != "" {
		return s.PGDump
	}
	return "pg_dump"
}

func (s Settings) pgRestore() string {
	if strings.TrimSpace(s.PGRestore) != "" {
		return s.PGRestore
	}
	return "pg_restore"
}

// ResolveIdentity resolves the runtime-injected age identity named by
// backup.encryption_key_ref. The reference is an environment variable name;
// its value is an age X25519 identity (AGE-SECRET-KEY-1…). Errors reference
// the key only — never the secret, never the referenced value.
func ResolveIdentity(ref string) (*age.X25519Identity, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("backup.encryption_key_ref: no runtime-injected key reference is configured")
	}
	val := strings.TrimSpace(os.Getenv(ref))
	if val == "" {
		return nil, fmt.Errorf("backup.encryption_key_ref: %s: the referenced secret is not set in the environment", ref)
	}
	id, err := age.ParseX25519Identity(val)
	if err != nil {
		return nil, fmt.Errorf("backup.encryption_key_ref: %s: the referenced secret is not a valid age identity", ref)
	}
	return id, nil
}

// Artifact describes one written encrypted backup.
type Artifact struct {
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// Create runs the logical dump of databaseURL (`pg_dump -Fc`), encrypts it
// with the settings' age recipient and writes it off-host into Dir, then
// prunes older artifacts down to the retention horizon. It returns the
// written artifact.
func Create(ctx context.Context, databaseURL string, s Settings) (Artifact, error) {
	if s.Identity == nil {
		return Artifact{}, errors.New("backup: no age identity configured")
	}
	dir := strings.TrimSpace(s.Dir)
	if dir == "" {
		return Artifact{}, errors.New("backup.dir: must not be empty (the off-host backup root)")
	}
	if err := os.MkdirAll(dir, backupDirMu); err != nil {
		return Artifact{}, fmt.Errorf("backup: create backup dir: %w", err)
	}

	now := time.Now().UTC()
	name := backupPrefix + now.Format("20060102T150405Z") + backupSuffix
	final := filepath.Join(dir, name)
	tmp := filepath.Join(dir, "."+name+".tmp")

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, backupPerm) // #nosec G304 -- tmp is a path this package built under backup.dir
	if err != nil {
		return Artifact{}, fmt.Errorf("backup: create artifact: %w", err)
	}
	// Remove the partial temp file on any failure.
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()

	encW, err := age.Encrypt(f, s.Identity.Recipient())
	if err != nil {
		return Artifact{}, fmt.Errorf("backup: start age encryption: %w", err)
	}
	if err := dumpTo(ctx, s, databaseURL, encW); err != nil {
		return Artifact{}, err
	}
	if err := encW.Close(); err != nil {
		return Artifact{}, fmt.Errorf("backup: finalize age encryption: %w", err)
	}
	if err := f.Close(); err != nil {
		return Artifact{}, fmt.Errorf("backup: finalize artifact: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return Artifact{}, fmt.Errorf("backup: commit artifact: %w", err)
	}
	committed = true

	size, sum, err := fileDigest(final)
	if err != nil {
		return Artifact{}, err
	}
	if _, err := Prune(dir, s.RetainDays, now); err != nil {
		return Artifact{}, err
	}
	return Artifact{Path: final, SizeBytes: size, SHA256: sum, CreatedAt: now}, nil
}

// dumpTo streams `pg_dump -Fc` of databaseURL into w.
func dumpTo(ctx context.Context, s Settings, databaseURL string, w io.Writer) error {
	args, env, err := pgToolArgs(databaseURL)
	if err != nil {
		return err
	}
	args = append([]string{"-Fc", "--no-owner", "--no-privileges"}, args...)
	// #nosec G204 -- the executable is the operator-configured pg_dump (PATH
	// default); the arguments are derived from the operator's database.url.
	cmd := exec.CommandContext(ctx, s.pgDump(), args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("backup: pg_dump stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("backup: start pg_dump: %w", err)
	}
	_, copyErr := io.Copy(w, stdout)
	waitErr := cmd.Wait()
	if copyErr != nil {
		return fmt.Errorf("backup: read pg_dump output: %w", copyErr)
	}
	if waitErr != nil {
		return fmt.Errorf("backup: pg_dump failed: %w: %s", waitErr, firstLine(stderr.String()))
	}
	return nil
}

// Decrypt decrypts the age artifact at srcPath into dstPath using identity.
// The plaintext dump is written 0600 and removed by the caller (or by the
// restore test's temp-file lifecycle).
func Decrypt(srcPath, dstPath string, identity *age.X25519Identity) error {
	if identity == nil {
		return errors.New("backup: no age identity configured")
	}
	// #nosec G304 -- srcPath is the operator-selected backup artifact under
	// backup.dir, never attacker-influenced input; opening it is the feature.
	in, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("backup: open artifact: %w", err)
	}
	defer in.Close()

	reader, err := age.Decrypt(in, identity)
	if err != nil {
		return fmt.Errorf("backup: decrypt artifact: %w", err)
	}
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, backupPerm) // #nosec G304 -- dstPath is the caller's decrypt target
	if err != nil {
		return fmt.Errorf("backup: create decrypted dump: %w", err)
	}
	if _, err := io.Copy(out, reader); err != nil {
		_ = out.Close()
		return fmt.Errorf("backup: write decrypted dump: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("backup: finalize decrypted dump: %w", err)
	}
	return nil
}

// Restore restores the plaintext logical dump at dumpPath into targetURL
// (`pg_restore --no-owner --no-privileges`). The target must be an empty
// instance: the restore test creates a throwaway database for exactly that.
func Restore(ctx context.Context, targetURL, dumpPath string, s Settings) error {
	args, env, err := pgToolArgs(targetURL)
	if err != nil {
		return err
	}
	args = append([]string{"--no-owner", "--no-privileges"}, args...)
	// #nosec G304 -- dumpPath is the decrypted artifact the restore test just
	// produced under its own temp dir, never attacker-influenced input.
	dump, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("backup: open dump: %w", err)
	}
	defer dump.Close()

	// #nosec G204 -- the executable is the operator-configured pg_restore
	// (PATH default); the arguments are derived from the target url.
	cmd := exec.CommandContext(ctx, s.pgRestore(), args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = dump
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("backup: pg_restore failed: %w: %s", err, firstLine(stderr.String()))
	}
	return nil
}

// Latest returns the newest encrypted backup in dir (by modification time),
// or a not-found error when the directory holds no artifact.
func Latest(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("backup: read backup dir: %w", err)
	}
	type cand struct {
		name string
		mod  time.Time
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), backupSuffix) || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return "", fmt.Errorf("backup: stat artifact: %w", err)
		}
		cands = append(cands, cand{name: e.Name(), mod: info.ModTime()})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("backup: no encrypted backup found in %s", dir)
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].mod.Equal(cands[j].mod) {
			return cands[i].name > cands[j].name
		}
		return cands[i].mod.After(cands[j].mod)
	})
	return filepath.Join(dir, cands[0].name), nil
}

// Prune removes artifacts older than retainDays, keeping the ≥14 daily states
// ARCH-007 §4 requires (the floor is enforced by the config validation). It
// returns the removed paths.
func Prune(dir string, retainDays int, now time.Time) ([]string, error) {
	if retainDays <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("backup: read backup dir: %w", err)
	}
	cutoff := now.Add(-time.Duration(retainDays) * 24 * time.Hour)
	var removed []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), backupSuffix) || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return removed, fmt.Errorf("backup: stat artifact: %w", err)
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dir, e.Name())
			if err := os.Remove(path); err != nil {
				return removed, fmt.Errorf("backup: prune artifact: %w", err)
			}
			removed = append(removed, path)
		}
	}
	return removed, nil
}

// pgToolArgs derives the pg_dump/pg_restore connection arguments for
// databaseURL. Credentials never travel on the command line: the password
// goes through PGPASSWORD and the sslmode through PGSSLMODE.
func pgToolArgs(databaseURL string) (args []string, env []string, err error) {
	u, err := url.Parse(strings.TrimSpace(databaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil, errors.New("backup: database url is not a valid connection URL")
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return nil, nil, errors.New("backup: database url names no database")
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	args = []string{"-h", host, "-p", port}
	if user := u.User.Username(); user != "" {
		args = append(args, "-U", user)
	}
	if pass, ok := u.User.Password(); ok {
		env = append(env, "PGPASSWORD="+pass)
	}
	if ssl := u.Query().Get("sslmode"); ssl != "" {
		env = append(env, "PGSSLMODE="+ssl)
	}
	args = append(args, "-d", db)
	return args, env, nil
}

// fileDigest returns the size and lower-case hex SHA-256 of a file.
func fileDigest(path string) (int64, string, error) {
	// #nosec G304 -- path is an artifact this package just wrote.
	f, err := os.Open(path)
	if err != nil {
		return 0, "", fmt.Errorf("backup: open artifact: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", fmt.Errorf("backup: hash artifact: %w", err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// firstLine returns the first non-empty line of s, trimmed; used to surface a
// pg tool's diagnostic without echoing a multi-line blob.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}
