/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"time"

	"github.com/gravitational/trace"

	accesslistpb "github.com/gravitational/teleport/api/gen/proto/go/accesslist/v1"
	"github.com/gravitational/teleport/api/types/common"
)

// FromAccessListV1 converts a v1 access list into an internal access list object.
func FromAccessListV1(msg *accesslistpb.AccessListV1) (*AccessList, error) {
	owners := make([]*AccessListOwner, len(msg.Spec.Owners))
	for i, owner := range msg.Spec.Owners {
		owners[i] = &AccessListOwner{
			Name:        owner.Name,
			Description: owner.Description,
		}
	}

	members := make([]*AccessListMember, len(msg.Spec.Members))
	for i, member := range msg.Spec.Members {
		members[i] = &AccessListMember{
			Name:    member.Name,
			Joined:  member.Joined.AsTime(),
			Expires: member.Expires.AsTime(),
			Reason:  member.Reason,
			AddedBy: member.AddedBy,
		}
	}

	accessList, err := NewAccessList(common.FromMetadataV1(msg.Header.Metadata), &AccessListSpec{
		Owners: owners,
		Audit: &AccessListAudit{
			Frequency: msg.Spec.Audit.Frequency.AsDuration(),
		},
		MembershipRequires: &AccessListRequires{
			Roles:  msg.Spec.MembershipRequires.Roles,
			Traits: msg.Spec.MembershipRequires.Traits,
		},
		OwnershipRequires: &AccessListRequires{
			Roles:  msg.Spec.OwnershipRequires.Roles,
			Traits: msg.Spec.OwnershipRequires.Traits,
		},
		Grants: &AccessListGrants{
			Roles:  msg.Spec.Grants.Roles,
			Traits: msg.Spec.Grants.Traits,
		},
		Members: members,
	})

	return accessList, trace.Wrap(err)
}

// AccessList describes the basic building block of access grants, which are
// similar to access requests but for longer lived permissions that need to be
// regularly audited.
type AccessList struct {
	// ResourceHeader is the common resource header for all resources.
	*common.ResourceHeader

	// Spec is the specification for the access list.
	Spec *AccessListSpec `json:"spec" yaml:"spec"`
}

// AccessListSpec is the specification for an access list.
type AccessListSpec struct {
	// Description is a plaintext description of the access list.
	Description string `json:"description" yaml:"description"`

	// Owners is a list of owners of the access list.
	Owners []*AccessListOwner `json:"owners" yaml:"owners"`

	// Audit describes the frequency that this access list must be audited.
	Audit *AccessListAudit `json:"audit" yaml:"audit"`

	// MembershipRequires describes the requirements for a user to be a member of the access list.
	// For a membership to an access list to be effective, the user must meet the requirements of
	// MembershipRequires and must be in the members list.
	MembershipRequires *AccessListRequires `json:"membership_requires" yaml:"membership_requires"`

	// OwnershipRequires describes the requirements for a user to be an owner of the access list.
	// For ownership of an access list to be effective, the user must meet the requirements of
	// OwnershipRequires and must be in the owners list.
	OwnershipRequires *AccessListRequires `json:"ownership_requires" yaml:"ownership_requires"`

	// Grants describes the access granted by membership to this access list.
	Grants *AccessListGrants `json:"grants" yaml:"grants"`

	// Members describes the current members of the access list.
	Members []*AccessListMember `json:"members" yaml:"members"`
}

// AccessListOwner is an owner of an access list.
type AccessListOwner struct {
	// Name is the username of the owner.
	Name string `json:"name" yaml:"name"`

	// Description is the plaintext description of the owner and why they are an owner.
	Description string `json:"description" yaml:"description"`
}

// AccessListAudit describes the audit configuration for an access list.
type AccessListAudit struct {
	// Frequency is a duration that describes how often an access list must be audited.
	Frequency time.Duration `json:"frequency" yaml:"frequency"`
}

// AccessListRequires describes a requirement section for an access list. A user must
// meet the following criteria to obtain the specific access to the list.
type AccessListRequires struct {
	// Roles are the user roles that must be present for the user to obtain access.
	Roles []string `json:"roles" yaml:"roles"`

	// Traits are the traits that must be present for the user to obtain access.
	Traits map[string]string `json:"traits" yaml:"traits"`
}

// AccessListGrants describes what access is granted by membership to the access list.
type AccessListGrants struct {
	// Roles are the roles that are granted to users who are members of the access list.
	Roles []string `json:"roles" yaml:"roles"`

	// Traits are the traits that are granted to users who are members of the access list.
	Traits map[string]string `json:"traits" yaml:"traits"`
}

// AccessListMember describes a member of an access list.
type AccessListMember struct {
	// Name is the name of the member of the access list.
	Name string `json:"name" yaml:"name"`

	// Joined is when the user joined the access list.
	Joined time.Time `json:"joined" yaml:"joined"`

	// expires is when the user's membership to the access list expires.
	Expires time.Time `json:"expires" yaml:"expires"`

	// reason is the reason this user was added to the access list.
	Reason string `json:"reason" yaml:"reason"`

	// added_by is the user that added this user to the access list.
	AddedBy string `json:"added_by" yaml:"added_by"`
}

// NewAccessList will create a new access list.
func NewAccessList(metadata *common.Metadata, spec *AccessListSpec) (*AccessList, error) {
	accessList := &AccessList{
		ResourceHeader: common.ResourceHeaderFromMetadata(metadata),
		Spec:           spec,
	}

	if err := accessList.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return accessList, nil
}

// CheckAndSetDefaults validates fields and populates empty fields with default values.
func (a *AccessList) CheckAndSetDefaults() error {
	a.SetKind(KindAccessList)
	a.SetVersion(V1)

	if err := a.ResourceHeader.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	if a.Spec == nil {
		return trace.BadParameter("spec is missing")
	}

	if len(a.Spec.Owners) == 0 {
		return trace.BadParameter("owners are missing")
	}

	for _, owner := range a.Spec.Owners {
		if owner.Name == "" {
			return trace.BadParameter("owner name is missing")
		}

		if owner.Description == "" {
			return trace.BadParameter("owner %s description is missing", owner.Name)
		}
	}

	if a.Spec.Audit == nil {
		return trace.BadParameter("audit is missing")
	}

	if a.Spec.Audit.Frequency == 0 {
		return trace.BadParameter("audit frequency must be greater than 0")
	}

	if a.Spec.Grants == nil {
		return trace.BadParameter("grants is missing")
	}

	if len(a.Spec.Grants.Roles) == 0 && len(a.Spec.Grants.Traits) == 0 {
		return trace.BadParameter("grants must specify at least one role or trait")
	}

	for _, member := range a.Spec.Members {
		if member.Name == "" {
			return trace.BadParameter("member name is missing")
		}

		if member.Joined.IsZero() {
			return trace.BadParameter("member %s joined is missing", member.Name)
		}

		if member.Expires.IsZero() {
			return trace.BadParameter("member %s expires is missing", member.Name)
		}

		if member.Reason == "" {
			return trace.BadParameter("member %s reason is missing", member.Name)
		}

		if member.AddedBy == "" {
			return trace.BadParameter("member %s added by is missing", member.Name)
		}
	}

	return nil
}

// GetOwners returns the list of owners from the access list.
func (a *AccessList) GetOwners() []*AccessListOwner {
	return a.Spec.Owners
}

// GetAuditFrequency returns the audit frequency from the access list.
func (a *AccessList) GetAuditFrequency() time.Duration {
	return a.Spec.Audit.Frequency
}

// GetMembershipRequires returns the membership requires configuration from the access list.
func (a *AccessList) GetMembershipRequires() *AccessListRequires {
	return a.Spec.MembershipRequires
}

// GetOwnershipRequires returns the ownership requires configuration from the access list.
func (a *AccessList) GetOwnershipRequires() *AccessListRequires {
	return a.Spec.OwnershipRequires
}

// GetGrants returns the grants from the access list.
func (a *AccessList) GetGrants() *AccessListGrants {
	return a.Spec.Grants
}

// GetMembers returns the members from the access list.
func (a *AccessList) GetMembers() []*AccessListMember {
	return a.Spec.Members
}
