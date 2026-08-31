// Package model holds the two persisted entities, USER and AUTHORITY, and the
// JSON projection of them that UserRestController returns.
package model

import (
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/javautil"
)

// Authority is a granted role. In the database it is a single-column table
// keyed by NAME.
type Authority struct {
	Name string `json:"name"`
}

// User is an account. The JSON tags reproduce the entity's Jackson annotations:
// ID, PASSWORD and ACTIVATED are @JsonIgnore, and the remaining members are
// emitted in declaration order.
type User struct {
	ID          int64       `json:"-"`
	Username    string      `json:"username"`
	Password    string      `json:"-"`
	Firstname   string      `json:"firstname"`
	Lastname    string      `json:"lastname"`
	Email       string      `json:"email"`
	Activated   bool        `json:"-"`
	Authorities []Authority `json:"authorities"`
}

// AuthorityNames returns the authority names in the order they are held.
func (u User) AuthorityNames() []string {
	names := make([]string, len(u.Authorities))
	for i, authority := range u.Authorities {
		names[i] = authority.Name
	}
	return names
}

// SetAuthorities stores authorities in the order a java.util.HashSet<Authority>
// would iterate them.
//
// The entity declares its authorities as a HashSet, and Jackson serialises the
// set as it iterates. For the admin account that is ROLE_USER before
// ROLE_ADMIN, which is neither alphabetical nor the order the join table rows
// were inserted in, so it can only be reproduced by bucketing the elements the
// way HashMap does.
func (u *User) SetAuthorities(authorities []Authority) {
	u.Authorities = javautil.HashSetOrder(authorities, authorityHash)
}

// authorityHash is Authority#hashCode: Objects.hash(name).
func authorityHash(a Authority) int32 {
	return javautil.ObjectsHash(javautil.StringHashCode(a.Name))
}
