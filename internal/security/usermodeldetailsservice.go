package security

import (
	"context"
	"errors"
	"strings"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/hibernatevalidator"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/model"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/repository"
)

// UserModelDetailsService authenticates a user from the database.
type UserModelDetailsService struct {
	userRepository *repository.UserRepository
	log            *logging.Logger
}

// NewUserModelDetailsService builds the service.
func NewUserModelDetailsService(userRepository *repository.UserRepository, log *logging.Logger) *UserModelDetailsService {
	return &UserModelDetailsService{userRepository: userRepository, log: log}
}

// LoadUserByUsername resolves a login to an account.
//
// Which column is searched depends on whether the login parses as an email
// address: an email is matched against EMAIL case-insensitively, anything else
// is lowercased and matched against USERNAME. The activation check happens
// before any password comparison, so a deactivated account reports that it is
// deactivated even when the password is also wrong.
func (s *UserModelDetailsService) LoadUserByUsername(ctx context.Context, login string) (UserDetails, error) {
	s.log.Debug("Authenticating user '%s'", login)

	if hibernatevalidator.IsValidEmail(login) {
		user, err := s.userRepository.FindOneWithAuthoritiesByEmailIgnoreCase(ctx, login)
		if err != nil {
			return UserDetails{}, notFound(err, "User with email "+login+" was not found in the database")
		}
		return createSecurityUser(login, user)
	}

	// The original lowercases with Locale.ENGLISH rather than the default
	// locale, so that a Turkish default cannot fold "I" to a dotless i.
	// strings.ToLower is locale-invariant and so agrees with it.
	lowercaseLogin := strings.ToLower(login)
	user, err := s.userRepository.FindOneWithAuthoritiesByUsername(ctx, lowercaseLogin)
	if err != nil {
		return UserDetails{}, notFound(err, "User "+lowercaseLogin+" was not found in the database")
	}
	return createSecurityUser(lowercaseLogin, user)
}

func createSecurityUser(lowercaseLogin string, user model.User) (UserDetails, error) {
	if !user.Activated {
		return UserDetails{}, &NotActivatedError{Login: lowercaseLogin}
	}
	return NewUserDetails(user.Username, user.Password, user.AuthorityNames()), nil
}

// notFound turns a missing row into a UsernameNotFoundError. Its message never
// reaches the client: the authentication manager replaces it with
// ErrBadCredentials so a caller cannot probe which accounts exist.
func notFound(err error, message string) error {
	if errors.Is(err, repository.ErrNotFound) {
		return &UsernameNotFoundError{Message: message}
	}
	return err
}

// UsernameNotFoundError reports that no account matched the login.
type UsernameNotFoundError struct {
	Message string
}

func (e *UsernameNotFoundError) Error() string { return e.Message }
