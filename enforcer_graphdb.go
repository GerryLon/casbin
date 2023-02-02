// Copyright 2017 The casbin Authors. All Rights Reserved.
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

package casbin

import (
	"sync"

	"github.com/Knetic/govaluate"

	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/rbac"
	defaultrolemanager "github.com/casbin/casbin/v2/rbac/default-role-manager"
)

// GraphdbEnforcer wraps Enforcer and provides synchronized access
type GraphdbEnforcer struct {
	*Enforcer
	m sync.RWMutex
}

// NewGraphdbEnforcer creates a synchronized enforcer via file or DB.
func NewGraphdbEnforcer(params ...interface{}) (*GraphdbEnforcer, error) {
	e := &GraphdbEnforcer{}
	var err error
	e.Enforcer, err = NewEnforcer(params...)
	if err != nil {
		return nil, err
	}

	return e, nil
}

// GetLock return the private RWMutex lock
func (e *GraphdbEnforcer) GetLock() *sync.RWMutex {
	return &e.m
}

// SetWatcher sets the current watcher.
func (e *GraphdbEnforcer) SetWatcher(watcher persist.Watcher) error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SetWatcher(watcher)
}

// LoadModel reloads the model from the model CONF file.
func (e *GraphdbEnforcer) LoadModel() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadModel()
}

// ClearPolicy clears all policy.
func (e *GraphdbEnforcer) ClearPolicy() {
	e.m.Lock()
	defer e.m.Unlock()
	e.Enforcer.ClearPolicy()
}

// LoadPolicy reloads the policy from file/database.
func (e *GraphdbEnforcer) LoadPolicy() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadPolicy()
}

// LoadPolicyFast is not blocked when adapter calls LoadPolicy.
func (e *GraphdbEnforcer) LoadPolicyFast() error {
	e.m.RLock()
	newModel := e.model.Copy()
	e.m.RUnlock()

	newModel.ClearPolicy()
	newRmMap := map[string]rbac.RoleManager{}
	var err error

	if err = e.adapter.LoadPolicy(newModel); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	if err = newModel.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err = newModel.SortPoliciesByPriority(); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		for ptype := range newModel["g"] {
			newRmMap[ptype] = defaultrolemanager.NewRoleManager(10)
		}
		err = newModel.BuildRoleLinks(newRmMap)
		if err != nil {
			return err
		}
	}

	// reduce the lock range
	e.m.Lock()
	defer e.m.Unlock()
	e.model = newModel
	e.rmMap = newRmMap
	return nil
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
func (e *GraphdbEnforcer) LoadFilteredPolicy(filter interface{}) error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadFilteredPolicy(filter)
}

// LoadIncrementalFilteredPolicy reloads a filtered policy from file/database.
func (e *GraphdbEnforcer) LoadIncrementalFilteredPolicy(filter interface{}) error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadIncrementalFilteredPolicy(filter)
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *GraphdbEnforcer) SavePolicy() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SavePolicy()
}

// BuildRoleLinks manually rebuild the role inheritance relations.
func (e *GraphdbEnforcer) BuildRoleLinks() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.BuildRoleLinks()
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *GraphdbEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.Enforce(rvals...)
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *GraphdbEnforcer) EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.EnforceWithMatcher(matcher, rvals...)
}

// EnforceEx explain enforcement by informing matched rules
func (e *GraphdbEnforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.EnforceEx(rvals...)
}

// EnforceExWithMatcher use a custom matcher and explain enforcement by informing matched rules
func (e *GraphdbEnforcer) EnforceExWithMatcher(matcher string, rvals ...interface{}) (bool, []string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.EnforceExWithMatcher(matcher, rvals...)
}

// BatchEnforce enforce in batches
func (e *GraphdbEnforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.BatchEnforce(requests)
}

// BatchEnforceWithMatcher enforce with matcher in batches
func (e *GraphdbEnforcer) BatchEnforceWithMatcher(matcher string, requests [][]interface{}) ([]bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.BatchEnforceWithMatcher(matcher, requests)
}

// GetAllSubjects gets the list of subjects that show up in the current policy.
func (e *GraphdbEnforcer) GetAllSubjects() []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllSubjects()
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
func (e *GraphdbEnforcer) GetAllNamedSubjects(ptype string) []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedSubjects(ptype)
}

// GetAllObjects gets the list of objects that show up in the current policy.
func (e *GraphdbEnforcer) GetAllObjects() []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllObjects()
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
func (e *GraphdbEnforcer) GetAllNamedObjects(ptype string) []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedObjects(ptype)
}

// GetAllActions gets the list of actions that show up in the current policy.
func (e *GraphdbEnforcer) GetAllActions() []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllActions()
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
func (e *GraphdbEnforcer) GetAllNamedActions(ptype string) []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedActions(ptype)
}

// GetAllRoles gets the list of roles that show up in the current policy.
func (e *GraphdbEnforcer) GetAllRoles() []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllRoles()
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
func (e *GraphdbEnforcer) GetAllNamedRoles(ptype string) []string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedRoles(ptype)
}

// GetPolicy gets all the authorization rules in the policy.
func (e *GraphdbEnforcer) GetPolicy() [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetPolicy()
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
func (e *GraphdbEnforcer) GetFilteredPolicy(fieldIndex int, fieldValues ...string) [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredPolicy(fieldIndex, fieldValues...)
}

// GetNamedPolicy gets all the authorization rules in the named policy.
func (e *GraphdbEnforcer) GetNamedPolicy(ptype string) [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetNamedPolicy(ptype)
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
func (e *GraphdbEnforcer) GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredNamedPolicy(ptype, fieldIndex, fieldValues...)
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
func (e *GraphdbEnforcer) GetGroupingPolicy() [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetGroupingPolicy()
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *GraphdbEnforcer) GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredGroupingPolicy(fieldIndex, fieldValues...)
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
func (e *GraphdbEnforcer) GetNamedGroupingPolicy(ptype string) [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetNamedGroupingPolicy(ptype)
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *GraphdbEnforcer) GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues...)
}

// HasPolicy determines whether an authorization rule exists.
func (e *GraphdbEnforcer) HasPolicy(params ...interface{}) bool {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasPolicy(params...)
}

// HasNamedPolicy determines whether a named authorization rule exists.
func (e *GraphdbEnforcer) HasNamedPolicy(ptype string, params ...interface{}) bool {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasNamedPolicy(ptype, params...)
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *GraphdbEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPolicy(params...)
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
func (e *GraphdbEnforcer) AddPolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPolicies(rules)
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *GraphdbEnforcer) AddNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPolicy(ptype, params...)
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
func (e *GraphdbEnforcer) AddNamedPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPolicies(ptype, rules)
}

// RemovePolicy removes an authorization rule from the current policy.
func (e *GraphdbEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemovePolicy(params...)
}

// UpdatePolicy updates an authorization rule from the current policy.
func (e *GraphdbEnforcer) UpdatePolicy(oldPolicy []string, newPolicy []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdatePolicy(oldPolicy, newPolicy)
}

func (e *GraphdbEnforcer) UpdateNamedPolicy(ptype string, p1 []string, p2 []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedPolicy(ptype, p1, p2)
}

// UpdatePolicies updates authorization rules from the current policies.
func (e *GraphdbEnforcer) UpdatePolicies(oldPolices [][]string, newPolicies [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdatePolicies(oldPolices, newPolicies)
}

func (e *GraphdbEnforcer) UpdateNamedPolicies(ptype string, p1 [][]string, p2 [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedPolicies(ptype, p1, p2)
}

func (e *GraphdbEnforcer) UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateFilteredPolicies(newPolicies, fieldIndex, fieldValues...)
}

func (e *GraphdbEnforcer) UpdateFilteredNamedPolicies(ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateFilteredNamedPolicies(ptype, newPolicies, fieldIndex, fieldValues...)
}

// RemovePolicies removes authorization rules from the current policy.
func (e *GraphdbEnforcer) RemovePolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemovePolicies(rules)
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
func (e *GraphdbEnforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
func (e *GraphdbEnforcer) RemoveNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedPolicy(ptype, params...)
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
func (e *GraphdbEnforcer) RemoveNamedPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedPolicies(ptype, rules)
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
func (e *GraphdbEnforcer) RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredNamedPolicy(ptype, fieldIndex, fieldValues...)
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
func (e *GraphdbEnforcer) HasGroupingPolicy(params ...interface{}) bool {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasGroupingPolicy(params...)
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
func (e *GraphdbEnforcer) HasNamedGroupingPolicy(ptype string, params ...interface{}) bool {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasNamedGroupingPolicy(ptype, params...)
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *GraphdbEnforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPolicy(params...)
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *GraphdbEnforcer) AddGroupingPolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPolicies(rules)
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *GraphdbEnforcer) AddNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPolicy(ptype, params...)
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *GraphdbEnforcer) AddNamedGroupingPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPolicies(ptype, rules)
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
func (e *GraphdbEnforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveGroupingPolicy(params...)
}

// RemoveGroupingPolicies removes role inheritance rules from the current policy.
func (e *GraphdbEnforcer) RemoveGroupingPolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveGroupingPolicies(rules)
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
func (e *GraphdbEnforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredGroupingPolicy(fieldIndex, fieldValues...)
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
func (e *GraphdbEnforcer) RemoveNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedGroupingPolicy(ptype, params...)
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
func (e *GraphdbEnforcer) RemoveNamedGroupingPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedGroupingPolicies(ptype, rules)
}

func (e *GraphdbEnforcer) UpdateGroupingPolicy(oldRule []string, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateGroupingPolicy(oldRule, newRule)
}

func (e *GraphdbEnforcer) UpdateGroupingPolicies(oldRules [][]string, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateGroupingPolicies(oldRules, newRules)
}

func (e *GraphdbEnforcer) UpdateNamedGroupingPolicy(ptype string, oldRule []string, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedGroupingPolicy(ptype, oldRule, newRule)
}

func (e *GraphdbEnforcer) UpdateNamedGroupingPolicies(ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedGroupingPolicies(ptype, oldRules, newRules)
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
func (e *GraphdbEnforcer) RemoveFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues...)
}

// AddFunction adds a customized function.
func (e *GraphdbEnforcer) AddFunction(name string, function govaluate.ExpressionFunction) {
	e.m.Lock()
	defer e.m.Unlock()
	e.Enforcer.AddFunction(name, function)
}
