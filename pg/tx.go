package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Beginner is implemented by pgxpool.Pool and other pgx transaction owners.
type Beginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// WithTx owns begin, rollback, and commit around fn.
func WithTx(ctx context.Context, beginner Beginner, fn func(pgx.Tx) error) error {
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback transaction: %w", rollbackErr))
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
