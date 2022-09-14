package domain

import "strings"

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (rolePerm RolePermissions) IsAuthorizedFor(role string, routeName string) bool {
	// grab the permissions from the rolePermissions map at key "role" - role may be user or admin or...
	permissions := rolePerm.rolePermissions[role]
	// range across each permission and compare the routeName provided with all leading and trailing white space removed
	// if they match, return true, otherwise return false
	for _, perm := range permissions {
		if perm == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{rolePermissions: map[string][]string{
		"user":  {"GetCustomer", "NewTransaction"},
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
	}}
}
