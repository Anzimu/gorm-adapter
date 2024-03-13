// Copyright 2023 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gormadapter

import (
	"context"
	"database/sql"
	"errors"
	"github.com/anzimu/casbin/v2"
	"github.com/anzimu/casbin/v2/model"
	"gorm.io/gorm"
	"log"
)

var CtxWithoutDBError = errors.New("[casbin] gorm adapter error: db does not within context")

type ContextAdapter struct {
	*Adapter
	gormCtxKey interface{}
}

func NewContextAdapter(gormCtxKey interface{}, driverName string, dataSourceName string, params ...interface{}) (*ContextAdapter, error) {
	a, err := NewAdapter(driverName, dataSourceName, params...)
	return &ContextAdapter{
		a,
		gormCtxKey,
	}, err
}

func NewContextAdapterByDBWithCustomTable(gormCtxKey interface{}, db *gorm.DB, t interface{}, tableName string, autoMigrate ...bool) (*ContextAdapter, error) {
	a, err := NewAdapterByDBWithCustomTable(db, t, tableName, autoMigrate...)
	return &ContextAdapter{
		a,
		gormCtxKey,
	}, err
}

// executeWithContext is a helper function to execute a function with context and return the result or error.
func executeWithContext(ctx context.Context, fn func() error) error {
	done := make(chan error)
	go func() {
		done <- fn()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// executeWithContext is a helper function to execute a function with context and return the result or error.
func executeWithContextEx(ctx context.Context, fn func() ([][]string, error)) ([][]string, error) {
	done := make(chan []interface{})
	go func() {
		rules, err := fn()
		done <- []interface{}{rules, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-done:
		return res[0].([][]string), res[1].(error)
	}
}

func (ca *ContextAdapter) getDBByCtx(ctx context.Context) (*gorm.DB, bool) {
	db, ok := ctx.Value(ca.gormCtxKey).(*gorm.DB)
	return db, ok
}

// TransactionCtx perform a set of operations within a transaction
func (ca *ContextAdapter) TransactionCtx(ctx context.Context, e casbin.ISyncedContextEnforcer,
	fc func(ctxEx context.Context, tx *gorm.DB) error, opts ...*sql.TxOptions) error {
	panicked := true
	var err error

	db, ok := ca.getDBByCtx(ctx)
	if !ok {
		return CtxWithoutDBError
	}
	tx := db.Begin(opts...)
	if tx.Error != nil {
		return tx.Error
	}
	// Set transaction db into the ctx
	ctxEx := context.WithValue(ctx, ca.gormCtxKey, tx)

	defer func() {
		// Make sure to rollback when panic, Block error or Commit error
		if panicked || err != nil {
			tx.Rollback()
			if err = e.LoadPolicySyncWatcher(); err != nil {
				log.Println(err)
			}
			return
		}
	}()

	if err = fc(ctxEx, tx); err == nil {
		panicked = false
		tx.Commit()
		if tx.Error != nil {
			return tx.Error
		}
		return nil
	}

	panicked = false
	return err
}

// LoadPolicyCtx loads all policy rules from the storage with context.
func (ca *ContextAdapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.loadPolicy(db, model)
	})
}

// LoadFilteredPolicyCtx loads only policy rules that match the filter.
func (ca *ContextAdapter) LoadFilteredPolicyCtx(ctx context.Context, model model.Model, filter interface{}) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.loadFilteredPolicy(db, model, filter)
	})
}

// SavePolicyCtx saves all policy rules to the storage with context.
func (ca *ContextAdapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.savePolicy(db, model)
	})
}

// AddPolicyCtx adds a policy rule to the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.addPolicy(db, sec, ptype, rule)
	})
}

// AddPoliciesCtx adds policy rules to the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) AddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.addPolicies(db, sec, ptype, rules)
	})
}

// RemovePolicyCtx removes a policy rule from the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.removePolicy(db, sec, ptype, rule)
	})
}

// RemovePoliciesCtx removes a policy rule from the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.removePolicies(db, sec, ptype, rules)
	})
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.removeFilteredPolicy(db, sec, ptype, fieldIndex, fieldValues...)
	})
}

// UpdatePolicyCtx updates a policy rule from storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) UpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule, newRule []string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.updatePolicy(db, sec, ptype, oldRule, newRule)
	})
}

// UpdatePoliciesCtx updates some policy rules to storage with context, like db, redis.
func (ca *ContextAdapter) UpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) error {
	return executeWithContext(ctx, func() error {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return CtxWithoutDBError
		}
		return ca.updatePolicies(db, sec, ptype, oldRules, newRules)
	})
}

// UpdateFilteredPoliciesCtx deletes old rules with context and adds new rules with context.
func (ca *ContextAdapter) UpdateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return executeWithContextEx(ctx, func() ([][]string, error) {
		db, ok := ca.getDBByCtx(ctx)
		if !ok {
			return nil, CtxWithoutDBError
		}
		return ca.updateFilteredPolicies(db, sec, ptype, newRules, fieldIndex, fieldValues...)
	})
}
