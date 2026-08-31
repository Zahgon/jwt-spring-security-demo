package security

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// AuthenticationManager checks a username and password against the account
// store, standing in for Spring Security's DaoAuthenticationProvider.
type AuthenticationManager struct {
	userDetailsService *UserModelDetailsService
}

// NewAuthenticationManager builds the manager.
func NewAuthenticationManager(userDetailsService *UserModelDetailsService) *AuthenticationManager {
	return &AuthenticationManager{userDetailsService: userDetailsService}
}

// Authenticate resolves the login and verifies the password.
//
// A login that matches no account is reported as ErrBadCredentials rather than
// as "no such user": DaoAuthenticationProvider hides UsernameNotFoundException
// by default so the endpoint cannot be used to enumerate accounts. Every other
// authentication failure — notably a deactivated account — keeps its own
// message and reaches the client.
func (m *AuthenticationManager) Authenticate(ctx context.Context, username, password string) (*Authentication, error) {
	userDetails, err := m.userDetailsService.LoadUserByUsername(ctx, username)
	if err != nil {
		var notFound *UsernameNotFoundError
		if errors.As(err, &notFound) {
			return nil, ErrBadCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userDetails.Password), []byte(password)); err != nil {
		return nil, ErrBadCredentials
	}

	return NewAuthentication(userDetails, password), nil
}
