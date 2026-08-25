package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/growth-labs/packages-go/testkit/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStartProvidesARealPostgreSQLServer(t *testing.T) {
	instance := postgres.Start(t)
	pool, err := pgxpool.New(context.Background(), instance.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var version string
	if err := pool.QueryRow(context.Background(), "SELECT version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "PostgreSQL ") {
		t.Fatalf("version() = %q, want PostgreSQL server", version)
	}
}
