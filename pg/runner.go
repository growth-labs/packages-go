package pg

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const createLedgerSQL = `
CREATE TABLE IF NOT EXISTS packages_go_schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL,
    export_created_at timestamptz,
    export_sha256 text,
    waiver_reason text
)`

// Runner applies migrations and records their versions.
type Runner struct {
	Now          func() time.Time
	Gate         ExportGate
	MaxExportAge time.Duration
}

// Apply runs every pending migration in its own transaction.
func (r Runner) Apply(ctx context.Context, pool *pgxpool.Pool, migrations []Migration, options ApplyOptions) error {
	if err := validateMigrations(migrations); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, createLedgerSQL); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	applied := make(map[int64]string)
	rows, err := pool.Query(ctx, `SELECT version, name FROM packages_go_schema_migrations`)
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	for rows.Next() {
		var version int64
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			rows.Close()
			return fmt.Errorf("scan migration ledger: %w", err)
		}
		applied[version] = name
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate migration ledger: %w", err)
	}
	rows.Close()

	pending := make([]Migration, 0, len(migrations))
	for _, migration := range migrations {
		if appliedName, ok := applied[migration.Version]; ok {
			if appliedName != migration.Name {
				return fmt.Errorf("migration ledger drift at version %d: applied name %q, supplied name %q", migration.Version, appliedName, migration.Name)
			}
			continue
		}
		pending = append(pending, migration)
	}
	if len(pending) == 0 {
		return nil
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	var receipt ExportReceipt
	if options.WaiveExport {
		if options.WaiverReason == "" {
			return fmt.Errorf("export waiver reason is required")
		}
	} else {
		if r.Gate == nil {
			return fmt.Errorf("pre-migration logical export is required")
		}
		verified, err := r.Gate.Verify(ctx)
		if err != nil {
			return fmt.Errorf("verify pre-migration logical export: %w", err)
		}
		receipt = verified
		if err := validateExportReceipt(receipt, now(), r.MaxExportAge); err != nil {
			return err
		}
	}
	for _, migration := range pending {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", migration.Version, err)
		}
		if _, err := tx.Exec(ctx, migration.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %d (%s): %w", migration.Version, migration.Name, err)
		}
		var exportCreatedAt any
		var exportSHA256 any
		if !options.WaiveExport {
			exportCreatedAt = receipt.CreatedAt.UTC()
			exportSHA256 = receipt.SHA256
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO packages_go_schema_migrations
			    (version, name, applied_at, export_created_at, export_sha256, waiver_reason)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			migration.Version, migration.Name, now().UTC(), exportCreatedAt, exportSHA256, options.WaiverReason); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %d: %w", migration.Version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", migration.Version, err)
		}
	}
	return nil
}

func validateMigrations(migrations []Migration) error {
	var previous int64
	for index, migration := range migrations {
		if migration.Version <= 0 {
			return fmt.Errorf("migration version must be positive: %d", migration.Version)
		}
		if index > 0 && migration.Version <= previous {
			return fmt.Errorf("migration versions must be strictly increasing: %d follows %d", migration.Version, previous)
		}
		if strings.TrimSpace(migration.Name) == "" {
			return fmt.Errorf("migration %d name is required", migration.Version)
		}
		if strings.TrimSpace(migration.SQL) == "" {
			return fmt.Errorf("migration %d SQL is required", migration.Version)
		}
		previous = migration.Version
	}
	return nil
}

func validateExportReceipt(receipt ExportReceipt, now time.Time, maxAge time.Duration) error {
	if receipt.CreatedAt.IsZero() {
		return fmt.Errorf("logical export timestamp is required")
	}
	if receipt.CreatedAt.After(now) {
		return fmt.Errorf("logical export timestamp is in the future")
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	if now.Sub(receipt.CreatedAt) > maxAge {
		return fmt.Errorf("logical export is stale: age %s exceeds %s", now.Sub(receipt.CreatedAt), maxAge)
	}
	digest, err := hex.DecodeString(receipt.SHA256)
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("logical export SHA-256 must be 64 hexadecimal characters")
	}
	return nil
}
