package pg_test

import (
	"context"
	"errors"
	"testing"

	"github.com/growth-labs/packages-go/pg"
	testpostgres "github.com/growth-labs/packages-go/testkit/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWithTxCommitsSuccessAndRollsBackCallbackFailure(t *testing.T) {
	instance := testpostgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), `CREATE TABLE tx_effects (label text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}

	if err := pg.WithTx(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO tx_effects (label) VALUES ('committed')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("reject callback")
	err = pg.WithTx(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO tx_effects (label) VALUES ('rolled back')`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx(callback failure) = %v, want sentinel", err)
	}

	var labels string
	if err := pool.QueryRow(context.Background(), `SELECT string_agg(label, ',' ORDER BY label) FROM tx_effects`).Scan(&labels); err != nil {
		t.Fatal(err)
	}
	if labels != "committed" {
		t.Fatalf("transaction effects = %q, want committed", labels)
	}
}
