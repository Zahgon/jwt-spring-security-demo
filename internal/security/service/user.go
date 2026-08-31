// Package service holds the application service that resolves the current
// request's principal to a persisted account.
package service

import (
	"context"
	"errors"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/model"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/repository"
)

// UserService reads the account behind the current principal.
type UserService struct {
	userRepository *repository.UserRepository
	securityUtils  *security.SecurityUtils
}

// NewUserService builds the service.
func NewUserService(userRepository *repository.UserRepository, securityUtils *security.SecurityUtils) *UserService {
	return &UserService{userRepository: userRepository, securityUtils: securityUtils}
}

// GetUserWithAuthorities loads the current user together with the authorities.
// It reports false when the request carries no principal, and equally when the
// principal names an account that no longer exists — a token outlives the row
// it was minted from, and the original's Optional is empty in both cases.
func (s *UserService) GetUserWithAuthorities(ctx context.Context) (model.User, bool, error) {
	username, ok := s.securityUtils.CurrentUsername(ctx)
	if !ok {
		return model.User{}, false, nil
	}

	user, err := s.userRepository.FindOneWithAuthoritiesByUsername(ctx, username)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return model.User{}, false, nil
	case err != nil:
		return model.User{}, false, err
	}
	return user, true, nil
}
