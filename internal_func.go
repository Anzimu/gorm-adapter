package gormadapter

import (
	"errors"
	"github.com/anzimu/casbin/v2/model"
	"gorm.io/gorm"
	"gorm.io/plugin/dbresolver"
)

// loadPolicy loads policy from database.
func (a *Adapter) loadPolicy(db *gorm.DB, model model.Model) error {
	var lines []CasbinRule
	if err := db.Scopes(a.casbinRuleTable()).Order("ID").Find(&lines).Error; err != nil {
		return err
	}
	err := a.Preview(&lines, model)
	if err != nil {
		return err
	}
	for _, line := range lines {
		err = loadPolicyLine(line, model)
		if err != nil {
			return err
		}
	}

	return nil
}

// loadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) loadFilteredPolicy(db *gorm.DB, model model.Model, filter interface{}) error {
	var lines []CasbinRule

	batchFilter := BatchFilter{
		filters: []Filter{},
	}
	switch filterValue := filter.(type) {
	case Filter:
		batchFilter.filters = []Filter{filterValue}
	case *Filter:
		batchFilter.filters = []Filter{*filterValue}
	case []Filter:
		batchFilter.filters = filterValue
	case BatchFilter:
		batchFilter = filterValue
	case *BatchFilter:
		batchFilter = *filterValue
	default:
		return errors.New("unsupported filter type")
	}

	for _, f := range batchFilter.filters {
		if err := db.Scopes(a.casbinRuleTable()).Scopes(a.filterQuery(a.db, f)).Order("ID").Find(&lines).Error; err != nil {
			return err
		}

		for _, line := range lines {
			err := loadPolicyLine(line, model)
			if err != nil {
				return err
			}
		}
	}
	a.isFiltered = true

	return nil
}

// savePolicy saves policy to database.
func (a *Adapter) savePolicy(db *gorm.DB, model model.Model) error {
	var err error
	tx := db.Scopes(a.casbinRuleTable()).Clauses(dbresolver.Write).Begin()

	err = a.truncateTable(db)

	if err != nil {
		tx.Rollback()
		return err
	}

	var lines []CasbinRule
	flushEvery := 1000
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				if err := tx.Create(&lines).Error; err != nil {
					tx.Rollback()
					return err
				}
				lines = nil
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				if err := tx.Create(&lines).Error; err != nil {
					tx.Rollback()
					return err
				}
				lines = nil
			}
		}
	}
	if len(lines) > 0 {
		if err := tx.Create(&lines).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit().Error
	return err
}

// addPolicy adds a policy rule to the storage.
func (a *Adapter) addPolicy(db *gorm.DB, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := db.Scopes(a.casbinRuleTable()).Create(&line).Error
	return err
}

// addPolicies adds multiple policy rules to the storage.
func (a *Adapter) addPolicies(db *gorm.DB, sec string, ptype string, rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		line := a.savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}
	return db.Scopes(a.casbinRuleTable()).Create(&lines).Error
}

// removePolicy removes a policy rule from the storage.
func (a *Adapter) removePolicy(db *gorm.DB, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := a.rawDelete(db, line) //can't use db.Delete as we're not using primary key https://gorm.io/docs/update.html
	return err
}

// removePolicies removes multiple policy rules from the storage.
func (a *Adapter) removePolicies(db *gorm.DB, sec string, ptype string, rules [][]string) error {
	return db.Scopes(a.casbinRuleTable()).Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			line := a.savePolicyLine(ptype, rule)
			if err := a.rawDelete(tx, line); err != nil { //can't use db.Delete as we're not using primary key https://gorm.io/docs/update.html
			}
		}
		return nil
	})
}

// removeFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) removeFilteredPolicy(db *gorm.DB, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := a.getTableInstance()
	tx := db.Scopes(a.casbinRuleTable())

	line.Ptype = ptype

	if fieldIndex == -1 {
		return a.rawDelete(tx, *line)
	}

	err := checkQueryField(fieldValues)
	if err != nil {
		return err
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	if fieldIndex <= 6 && 6 < fieldIndex+len(fieldValues) {
		line.V6 = fieldValues[6-fieldIndex]
	}
	if fieldIndex <= 7 && 7 < fieldIndex+len(fieldValues) {
		line.V7 = fieldValues[7-fieldIndex]
	}
	err = a.rawDelete(tx, *line)
	return err
}

// updatePolicy updates a new policy rule to DB.
func (a *Adapter) updatePolicy(db *gorm.DB, sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := a.savePolicyLine(ptype, oldRule)
	newLine := a.savePolicyLine(ptype, newPolicy)
	return db.Scopes(a.casbinRuleTable()).Model(&oldLine).Where(&oldLine).Updates(newLine).Error
}

func (a *Adapter) updatePolicies(db *gorm.DB, sec string, ptype string, oldRules, newRules [][]string) error {
	oldPolicies := make([]CasbinRule, 0, len(oldRules))
	newPolicies := make([]CasbinRule, 0, len(oldRules))
	for _, oldRule := range oldRules {
		oldPolicies = append(oldPolicies, a.savePolicyLine(ptype, oldRule))
	}
	for _, newRule := range newRules {
		newPolicies = append(newPolicies, a.savePolicyLine(ptype, newRule))
	}
	err := db.Scopes(a.casbinRuleTable()).Transaction(func(tx *gorm.DB) error {
		for i := range oldPolicies {
			if err := tx.Model(&oldPolicies[i]).Where(&oldPolicies[i]).Updates(newPolicies[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) updateFilteredPolicies(db *gorm.DB, sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	line := a.getTableInstance()

	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	if fieldIndex <= 6 && 6 < fieldIndex+len(fieldValues) {
		line.V6 = fieldValues[6-fieldIndex]
	}
	if fieldIndex <= 7 && 7 < fieldIndex+len(fieldValues) {
		line.V7 = fieldValues[7-fieldIndex]
	}

	newP := make([]CasbinRule, 0, len(newPolicies))
	oldP := make([]CasbinRule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, a.savePolicyLine(ptype, newRule))
	}

	tx := db.Scopes(a.casbinRuleTable()).Begin()
	str, args := line.queryString()
	if err := tx.Where(str, args...).Find(&oldP).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Where(str, args...).Delete([]CasbinRule{}).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	for i := range newP {
		if err := tx.Create(&newP[i]).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, tx.Commit().Error
}
