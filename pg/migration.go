// Package pg supplies ordered PostgreSQL migrations and transaction helpers.
package pg

// Migration is one immutable, forward-only SQL migration.
type Migration struct {
	Version     int64
	Name        string
	SQL         string
	DataBearing bool
}

// ApplyOptions controls the explicit pre-migration export waiver.
type ApplyOptions struct {
	WaiveExport  bool
	WaiverReason string
}
