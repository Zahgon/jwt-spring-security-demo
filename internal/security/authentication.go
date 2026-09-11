// Package security holds the authentication machinery the original gets from
// Spring Security: the authenticated principal, the per-request security
// context, the service that loads accounts from the database, and the two
// handlers that turn an authorisation failure into an HTTP response.
package security

import (
	"context"
	"sort"
)

// Authentication is an authenticated (or attempted) principal, the role
// org.springframework.security.core.Authentication plays in the original.
type Authentication struct {
	// Principal is the authenticated party. It is UserDetails once an account
	// has been loaded, and a bare username string before that.
	Principal any
	// Credentials is the presented credential: the raw password during login,
	// the token afterwards.
	Credentials string
	// Authorities are the granted authorities.
	Authorities []string
	// Authenticated distinguishes a completed authentication from a request
	// carrying only a candidate username and password.
	Authenticated bool
}

// Name returns the principal's name. As in Spring, it is the UserDetails
// username when the principal is a loaded account, and the string itself when
// the principal is a bare name.
func (a *Authentication) Name() string {
	switch principal := a.Principal.(type) {
	case UserDetails:
		return principal.Username
	case string:
		return principal
	default:
		return ""
	}
}

// HasAuthority reports whether the principal holds authority.
func (a *Authentication) HasAuthority(authority string) bool {
	for _, granted := range a.Authorities {
		if granted == authority {
			return true
		}
	}
	return false
}

// UserDetails is a loaded account,
// org.springframework.security.core.userdetails.User.
type UserDetails struct {
	Username string
	Password string
	// Authorities are held in ascending order. Spring's User keeps them in a
	// SortedSet, which is why the JWT "auth" claim reads ROLE_ADMIN,ROLE_USER
	// while the same account's /api/user response lists ROLE_USER first — that
	// one comes from the entity's HashSet instead.
	Authorities []string
}

// NewUserDetails builds a UserDetails, sorting the authorities the way Spring's
// User constructor does.
func NewUserDetails(username, password string, authorities []string) UserDetails {
	sorted := make([]string, len(authorities))
	copy(sorted, authorities)
	sort.Strings(sorted)
	return UserDetails{Username: username, Password: password, Authorities: sorted}
}

// NewAuthentication builds a completed authentication for a loaded account.
func NewAuthentication(principal UserDetails, credentials string) *Authentication {
	return &Authentication{
		Principal:     principal,
		Credentials:   credentials,
		Authorities:   principal.Authorities,
		Authenticated: true,
	}
}

type contextKey struct{}

// WithAuthentication returns a copy of ctx carrying auth.
//
// The original stores the authentication in a SecurityContextHolder, which is a
// ThreadLocal. Go's equivalent of "state scoped to the work in progress" is the
// request context, so the holder becomes a context value: it is inherently
// per-request, cannot leak between concurrent requests, and needs no clearing.
func WithAuthentication(ctx context.Context, auth *Authentication) context.Context {
	return context.WithValue(ctx, contextKey{}, auth)
}

// AuthenticationFrom returns the authentication carried by ctx, or nil.
func AuthenticationFrom(ctx context.Context) *Authentication {
	auth, _ := ctx.Value(contextKey{}).(*Authentication)
	return auth
}
