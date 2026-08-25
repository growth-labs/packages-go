// Package postgres starts real, disposable PostgreSQL servers for tests.
package postgres

import (
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

// Instance is a running test-only PostgreSQL server.
type Instance struct {
	url string
}

// URL returns the pgx-compatible connection URL for the running server.
func (i *Instance) URL() string {
	return i.url
}

// Start launches PostgreSQL 18 with isolated runtime and data directories.
// The downloaded archive may use the library cache, but every server process
// and database belongs to this test and is stopped during cleanup.
func Start(t testing.TB) *Instance {
	t.Helper()
	port := availablePort(t)
	root := t.TempDir()
	config := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V18).
		Port(port).
		RuntimePath(filepath.Join(root, "runtime")).
		DataPath(filepath.Join(root, "data")).
		StartTimeout(60 * time.Second).
		Logger(io.Discard)

	database := embeddedpostgres.NewDatabase(config)
	if err := database.Start(); err != nil {
		t.Fatalf("start embedded PostgreSQL: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Stop(); err != nil {
			t.Errorf("stop embedded PostgreSQL: %v", err)
		}
	})
	return &Instance{url: config.GetConnectionURL()}
}

func availablePort(t testing.TB) uint32 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve PostgreSQL port: %v", err)
	}
	portText := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatalf("release PostgreSQL port %s: %v", portText, err)
	}
	port, err := strconv.ParseUint(portText, 10, 32)
	if err != nil {
		t.Fatalf("parse PostgreSQL port %q: %v", portText, err)
	}
	return uint32(port)
}
