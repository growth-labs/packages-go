package pg

import (
	"context"
	"time"
)

// ExportReceipt identifies the logical export taken before migrations begin.
type ExportReceipt struct {
	CreatedAt time.Time
	SHA256    string
}

// ExportGate returns a verified logical-export receipt.
type ExportGate interface {
	Verify(context.Context) (ExportReceipt, error)
}

// ExportGateFunc adapts a function to ExportGate.
type ExportGateFunc func(context.Context) (ExportReceipt, error)

// Verify implements ExportGate.
func (f ExportGateFunc) Verify(ctx context.Context) (ExportReceipt, error) {
	return f(ctx)
}
