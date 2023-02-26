// Copyright 2019 The casbin Authors. All Rights Reserved.
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
	"context"

	"github.com/Knetic/govaluate"
	"github.com/casbin/casbin/v2/effector"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/rbac"
)

var _ IEnforcer = &Enforcer{}
var _ IEnforcer = &SyncedEnforcer{}
var _ IEnforcer = &CachedEnforcer{}

// IEnforcer is the API interface of Enforcer
type IEnforcer interface {
	/* Enforcer API */
	InitWithFile(modelPath string, policyPath string) error
	InitWithAdapter(modelPath string, adapter persist.Adapter) error
	InitWithModelAndAdapter(m model.Model, adapter persist.Adapter) error
	LoadModel() error
	GetModel() model.Model
	SetModel(m model.Model)
	GetAdapter() persist.Adapter
	SetAdapter(adapter persist.Adapter)
	SetWatcher(ctx context.Context, watcher persist.Watcher) error
	GetRoleManager() rbac.RoleManager
	SetRoleManager(rm rbac.RoleManager)
	SetEffector(eft effector.Effector)
	ClearPolicy(ctx context.Context) error
	LoadPolicy(ctx context.Context) error
	LoadFilteredPolicy(ctx context.Context, filter interface{}) error
	LoadIncrementalFilteredPolicy(ctx context.Context, filter interface{}) error
	IsFiltered() bool
	SavePolicy(ctx context.Context) error
	EnableEnforce(enable bool)
	EnableLog(enable bool)
	EnableAutoNotifyWatcher(enable bool)
	EnableAutoSave(autoSave bool)
	EnableAutoBuildRoleLinks(autoBuildRoleLinks bool)
	BuildRoleLinks(ctx context.Context) error
	Enforce(ctx context.Context, rvals ...interface{}) (bool, error)
	EnforceWithMatcher(ctx context.Context, matcher string, rvals ...interface{}) (bool, error)
	EnforceEx(ctx context.Context, rvals ...interface{}) (bool, []string, error)
	EnforceExWithMatcher(ctx context.Context, matcher string, rvals ...interface{}) (bool, []string, error)
	BatchEnforce(ctx context.Context, requests [][]interface{}) ([]bool, error)
	BatchEnforceWithMatcher(ctx context.Context, matcher string, requests [][]interface{}) ([]bool, error)

	/* RBAC API */
	GetRolesForUser(ctx context.Context, name string, domain ...string) ([]string, error)
	GetUsersForRole(ctx context.Context, name string, domain ...string) ([]string, error)
	HasRoleForUser(ctx context.Context, name string, role string, domain ...string) (bool, error)
	AddRoleForUser(ctx context.Context, user string, role string, domain ...string) (bool, error)
	AddPermissionForUser(ctx context.Context, user string, permission ...string) (bool, error)
	AddPermissionsForUser(ctx context.Context, user string, permissions ...[]string) (bool, error)
	DeletePermissionForUser(ctx context.Context, user string, permission ...string) (bool, error)
	DeletePermissionsForUser(ctx context.Context, user string) (bool, error)
	GetPermissionsForUser(ctx context.Context, user string, domain ...string) ([][]string, error)
	HasPermissionForUser(ctx context.Context, user string, permission ...string) (bool, error)
	GetImplicitRolesForUser(ctx context.Context, name string, domain ...string) ([]string, error)
	GetImplicitPermissionsForUser(ctx context.Context, user string, domain ...string) ([][]string, error)
	GetImplicitUsersForPermission(ctx context.Context, permission ...string) ([]string, error)
	DeleteRoleForUser(ctx context.Context, user string, role string, domain ...string) (bool, error)
	DeleteRolesForUser(ctx context.Context, user string, domain ...string) (bool, error)
	DeleteUser(ctx context.Context, user string) (bool, error)
	DeleteRole(ctx context.Context, role string) (bool, error)
	DeletePermission(ctx context.Context, permission ...string) (bool, error)

	/* RBAC API with domains*/
	GetUsersForRoleInDomain(ctx context.Context, name string, domain string) ([]string, error)
	GetRolesForUserInDomain(ctx context.Context, name string, domain string) ([]string, error)
	GetPermissionsForUserInDomain(ctx context.Context, user string, domain string) [][]string
	AddRoleForUserInDomain(ctx context.Context, user string, role string, domain string) (bool, error)
	DeleteRoleForUserInDomain(ctx context.Context, user string, role string, domain string) (bool, error)

	/* Management API */
	GetAllSubjects(ctx context.Context) ([]string, error)
	GetAllNamedSubjects(ctx context.Context, ptype string) ([]string, error)
	GetAllObjects(ctx context.Context) []string
	GetAllNamedObjects(ctx context.Context, ptype string) ([]string, error)
	GetAllActions(ctx context.Context) ([]string, error)
	GetAllNamedActions(ctx context.Context, ptype string) ([]string, error)
	GetAllRoles(ctx context.Context) ([]string, error)
	GetAllNamedRoles(ctx context.Context, ptype string) ([]string, error)
	GetPolicy(ctx context.Context) ([][]string, error)
	GetFilteredPolicy(ctx context.Context, fieldIndex int, fieldValues ...string) ([][]string, error)
	GetNamedPolicy(ctx context.Context, ptype string) ([][]string, error)
	GetFilteredNamedPolicy(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) ([][]string, error)
	GetGroupingPolicy(ctx context.Context) ([][]string, error)
	GetFilteredGroupingPolicy(ctx context.Context, fieldIndex int, fieldValues ...string) ([][]string, error)
	GetNamedGroupingPolicy(ctx context.Context, ptype string) ([][]string, error)
	GetFilteredNamedGroupingPolicy(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) ([][]string, error)
	HasPolicy(ctx context.Context, params ...interface{}) (bool, error)
	HasNamedPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	AddPolicy(ctx context.Context, params ...interface{}) (bool, error)
	AddPolicies(ctx context.Context, rules [][]string) (bool, error)
	AddNamedPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	AddNamedPolicies(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemovePolicy(ctx context.Context, params ...interface{}) (bool, error)
	RemovePolicies(ctx context.Context, rules [][]string) (bool, error)
	RemoveFilteredPolicy(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error)
	RemoveNamedPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	RemoveNamedPolicies(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemoveFilteredNamedPolicy(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	HasGroupingPolicy(ctx context.Context, params ...interface{}) (bool, error)
	HasNamedGroupingPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	AddGroupingPolicy(ctx context.Context, params ...interface{}) (bool, error)
	AddGroupingPolicies(ctx context.Context, rules [][]string) (bool, error)
	AddNamedGroupingPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	AddNamedGroupingPolicies(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemoveGroupingPolicy(ctx context.Context, params ...interface{}) (bool, error)
	RemoveGroupingPolicies(ctx context.Context, rules [][]string) (bool, error)
	RemoveFilteredGroupingPolicy(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error)
	RemoveNamedGroupingPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	RemoveNamedGroupingPolicies(ptype string, rules [][]string) (bool, error)
	RemoveFilteredNamedGroupingPolicy(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	AddFunction(name string, function govaluate.ExpressionFunction)

	UpdatePolicy(ctx context.Context, oldPolicy []string, newPolicy []string) (bool, error)
	UpdatePolicies(ctx context.Context, oldPolicies [][]string, newPolicies [][]string) (bool, error)
	UpdateFilteredPolicies(ctx context.Context, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error)

	UpdateGroupingPolicy(ctx context.Context, oldRule []string, newRule []string) (bool, error)
	UpdateGroupingPolicies(ctx context.Context, oldRules [][]string, newRules [][]string) (bool, error)

	/* Management API with autoNotifyWatcher disabled */
	SelfAddPolicy(ctx context.Context, sec string, ptype string, rule []string) (bool, error)
	SelfAddPolicies(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error)
	SelfRemovePolicy(ctx context.Context, sec string, ptype string, rule []string) (bool, error)
	SelfRemovePolicies(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error)
	SelfRemoveFilteredPolicy(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	SelfUpdatePolicy(ctx context.Context, sec string, ptype string, oldRule, newRule []string) (bool, error)
	SelfUpdatePolicies(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) (bool, error)
}

var _ IDistributedEnforcer = &DistributedEnforcer{}

// IDistributedEnforcer defines dispatcher enforcer.
type IDistributedEnforcer interface {
	IEnforcer
	SetDispatcher(dispatcher persist.Dispatcher)
	/* Management API for DistributedEnforcer*/
	AddPoliciesSelf(shouldPersist func() bool, sec string, ptype string, rules [][]string) (affected [][]string, err error)
	RemovePoliciesSelf(shouldPersist func() bool, sec string, ptype string, rules [][]string) (affected [][]string, err error)
	RemoveFilteredPolicySelf(shouldPersist func() bool, sec string, ptype string, fieldIndex int, fieldValues ...string) (affected [][]string, err error)
	ClearPolicySelf(shouldPersist func() bool) error
	UpdatePolicySelf(shouldPersist func() bool, sec string, ptype string, oldRule, newRule []string) (affected bool, err error)
	UpdatePoliciesSelf(shouldPersist func() bool, sec string, ptype string, oldRules, newRules [][]string) (affected bool, err error)
	UpdateFilteredPoliciesSelf(shouldPersist func() bool, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) (bool, error)
}
