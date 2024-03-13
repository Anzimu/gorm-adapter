package gormadapter

import (
	"context"
	"database/sql"
	"github.com/anzimu/casbin/v2"
	"github.com/anzimu/casbin/v2/persist"
	"gorm.io/gorm"
)

type ContextAdapterInterface interface {
	persist.ContextAdapter
	persist.FilteredContextAdapter
	persist.BatchContextAdapter
	persist.UpdatableContextAdapter

	// TransactionCtx perform a set of operations within a transaction
	TransactionCtx(ctx context.Context, e casbin.ISyncedContextEnforcer, fc func(ctxEx context.Context, tx *gorm.DB) error, opts ...*sql.TxOptions) error
}
