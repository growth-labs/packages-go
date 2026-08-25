package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/growth-labs/packages-go/pg"
	"github.com/growth-labs/packages-go/testkit"
	testpostgres "github.com/growth-labs/packages-go/testkit/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunnerAppliesMigrationsInOrderAndIsIdempotent(t *testing.T) {
	instance := testpostgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	migrations := []pg.Migration{
		{Version: 1, Name: "create effects", SQL: `
			CREATE TABLE migration_effects (position integer PRIMARY KEY, label text NOT NULL);
			INSERT INTO migration_effects (position, label) VALUES (1, 'first');`},
		{Version: 2, Name: "append effect", SQL: `
			INSERT INTO migration_effects (position, label) VALUES (2, 'second');`},
	}
	runner := pg.Runner{Now: func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }}
	if err := runner.Apply(context.Background(), pool, migrations, pg.ApplyOptions{
		WaiveExport:  true,
		WaiverReason: "empty disposable test database",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runner.Apply(context.Background(), pool, migrations, pg.ApplyOptions{}); err != nil {
		t.Fatalf("idempotent Apply() = %v", err)
	}

	var effects string
	if err := pool.QueryRow(context.Background(), `
		SELECT string_agg(label, ',' ORDER BY position) FROM migration_effects`).Scan(&effects); err != nil {
		t.Fatal(err)
	}
	if effects != "first,second" {
		t.Fatalf("effects = %q, want first,second", effects)
	}

	var applied int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM packages_go_schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Fatalf("ledger rows = %d, want 2", applied)
	}
}

func TestExportGateGuardIsFalsifiableAtRunnerApply(t *testing.T) {
	instance := testpostgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	runner := pg.Runner{Now: func() time.Time {
		return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	}}
	migrations := []pg.Migration{{
		Version: 1,
		Name:    "guard wiring proof",
		SQL:     `CREATE TABLE export_guard_proof (id bigint PRIMARY KEY)`,
	}}
	testkit.ProveGuard(t, func(mutation testkit.Mutation) error {
		options := pg.ApplyOptions{}
		if mutation.GuardsDisabled() {
			options.WaiveExport = true
			options.WaiverReason = "test mutation proving the gate can fail"
		}
		return runner.Apply(context.Background(), pool, migrations, options)
	})
}

func TestRunnerRejectsUnusableExportReceipts(t *testing.T) {
	instance := testpostgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	valid := pg.ExportReceipt{CreatedAt: now.Add(-5 * time.Minute), SHA256: strings.Repeat("b", 64)}
	tests := map[string]struct {
		receipt pg.ExportReceipt
		gateErr error
		want    string
	}{
		"missing timestamp": {receipt: pg.ExportReceipt{SHA256: valid.SHA256}, want: "timestamp"},
		"future timestamp":  {receipt: pg.ExportReceipt{CreatedAt: now.Add(time.Minute), SHA256: valid.SHA256}, want: "future"},
		"stale export":      {receipt: pg.ExportReceipt{CreatedAt: now.Add(-2 * time.Hour), SHA256: valid.SHA256}, want: "stale"},
		"invalid digest":    {receipt: pg.ExportReceipt{CreatedAt: valid.CreatedAt, SHA256: "not-a-sha256"}, want: "SHA-256"},
		"gate failure":      {gateErr: errors.New("logical export failed"), want: "logical export failed"},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			runner := pg.Runner{
				Now:          func() time.Time { return now },
				MaxExportAge: time.Hour,
				Gate: pg.ExportGateFunc(func(context.Context) (pg.ExportReceipt, error) {
					return testCase.receipt, testCase.gateErr
				}),
			}
			err := runner.Apply(context.Background(), pool, []pg.Migration{{
				Version: 1,
				Name:    "must remain pending",
				SQL:     `CREATE TABLE must_not_exist (id bigint)`,
			}}, pg.ApplyOptions{})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Apply() error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestRunnerRejectsInvalidAndDriftedMigrationLists(t *testing.T) {
	instance := testpostgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	invalid := map[string]struct {
		migrations []pg.Migration
		want       string
	}{
		"non-positive version": {migrations: []pg.Migration{{Version: 0, Name: "zero", SQL: "SELECT 1"}}, want: "positive"},
		"duplicate version": {migrations: []pg.Migration{
			{Version: 10, Name: "ten a", SQL: "SELECT 1"},
			{Version: 10, Name: "ten b", SQL: "SELECT 1"},
		}, want: "strictly increasing"},
		"descending versions": {migrations: []pg.Migration{
			{Version: 21, Name: "twenty one", SQL: "SELECT 1"},
			{Version: 20, Name: "twenty", SQL: "SELECT 1"},
		}, want: "strictly increasing"},
		"empty name": {migrations: []pg.Migration{{Version: 30, SQL: "SELECT 1"}}, want: "name"},
		"empty SQL":  {migrations: []pg.Migration{{Version: 40, Name: "empty"}}, want: "SQL"},
	}
	for name, testCase := range invalid {
		t.Run(name, func(t *testing.T) {
			err := (pg.Runner{}).Apply(context.Background(), pool, testCase.migrations, pg.ApplyOptions{
				WaiveExport: true, WaiverReason: "validation test",
			})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Apply() error = %v, want %q", err, testCase.want)
			}
		})
	}

	original := []pg.Migration{{Version: 50, Name: "stable identity", SQL: "SELECT 1"}}
	if err := (pg.Runner{}).Apply(context.Background(), pool, original, pg.ApplyOptions{
		WaiveExport: true, WaiverReason: "drift setup",
	}); err != nil {
		t.Fatal(err)
	}
	drifted := []pg.Migration{{Version: 50, Name: "changed identity", SQL: "SELECT 1"}}
	if err := (pg.Runner{}).Apply(context.Background(), pool, drifted, pg.ApplyOptions{}); err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("Apply(drifted) error = %v, want ledger drift", err)
	}
}

func TestRunnerAcceptsFreshLogicalExportReceipt(t *testing.T) {
	instance := testpostgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	receipt := pg.ExportReceipt{
		CreatedAt: now.Add(-5 * time.Minute),
		SHA256:    strings.Repeat("a", 64),
	}
	gateCalls := 0
	runner := pg.Runner{
		Now: func() time.Time { return now },
		Gate: pg.ExportGateFunc(func(context.Context) (pg.ExportReceipt, error) {
			gateCalls++
			return receipt, nil
		}),
	}
	migrations := []pg.Migration{{
		Version: 1,
		Name:    "create gated table",
		SQL:     `CREATE TABLE gated_table (id bigint PRIMARY KEY)`,
	}}
	if err := runner.Apply(context.Background(), pool, migrations, pg.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if gateCalls != 1 {
		t.Fatalf("export gate calls = %d, want 1", gateCalls)
	}

	var createdAt time.Time
	var digest string
	if err := pool.QueryRow(context.Background(), `
		SELECT export_created_at, export_sha256
		FROM packages_go_schema_migrations WHERE version = 1`).Scan(&createdAt, &digest); err != nil {
		t.Fatal(err)
	}
	if !createdAt.Equal(receipt.CreatedAt) || digest != receipt.SHA256 {
		t.Fatalf("ledger export = (%s, %q), want (%s, %q)", createdAt, digest, receipt.CreatedAt, receipt.SHA256)
	}

	runner.Gate = pg.ExportGateFunc(func(context.Context) (pg.ExportReceipt, error) {
		t.Fatal("export gate called with no pending migrations")
		return pg.ExportReceipt{}, nil
	})
	if err := runner.Apply(context.Background(), pool, migrations, pg.ApplyOptions{}); err != nil {
		t.Fatalf("idempotent Apply() = %v", err)
	}
}
