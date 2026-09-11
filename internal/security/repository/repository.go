// Package repository is the data-access layer, standing in for the two Spring
// Data JPA interfaces. Spring derived their SQL from the method names; here the
// same two queries are written out, each fetching the account together with its
// authorities the way the @EntityGraph(attributePaths = "authorities")
// annotation did.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/model"
)

// ErrNotFound reports that no row matched, standing in for the empty Optional
// the JPA repositories return.
var ErrNotFound = errors.New("user not found")

// UserRepository reads accounts.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository returns a repository backed by db.
func NewUserRepository(db *sql.DB) *UserRepository { return &UserRepository{db: db} }

const selectUser = `SELECT ID, USERNAME, PASSWORD, FIRSTNAME, LASTNAME, EMAIL, ACTIVATED FROM "USER" WHERE `

// FindOneWithAuthoritiesByUsername looks an account up by its exact username.
func (r *UserRepository) FindOneWithAuthoritiesByUsername(ctx context.Context, username string) (model.User, error) {
	return r.findOne(ctx, selectUser+"USERNAME = ?", username)
}

// FindOneWithAuthoritiesByEmailIgnoreCase looks an account up by email,
// ignoring case — the IgnoreCase suffix Spring Data turned into a
// lower(EMAIL) = lower(?) predicate.
func (r *UserRepository) FindOneWithAuthoritiesByEmailIgnoreCase(ctx context.Context, email string) (model.User, error) {
	return r.findOne(ctx, selectUser+"lower(EMAIL) = lower(?)", email)
}

func (r *UserRepository) findOne(ctx context.Context, query string, arg any) (model.User, error) {
	var user model.User
	err := r.db.QueryRowContext(ctx, query, arg).Scan(
		&user.ID, &user.Username, &user.Password, &user.Firstname, &user.Lastname, &user.Email, &user.Activated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return model.User{}, ErrNotFound
	case err != nil:
		return model.User{}, fmt.Errorf("querying user: %w", err)
	}

	authorities, err := r.findAuthorities(ctx, user.ID)
	if err != nil {
		return model.User{}, err
	}
	user.SetAuthorities(authorities)
	return user, nil
}

// findAuthorities fetches the account's authorities in join-table order, which
// is the order the entity's HashSet was populated in.
func (r *UserRepository) findAuthorities(ctx context.Context, userID int64) ([]model.Authority, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT AUTHORITY_NAME FROM USER_AUTHORITY WHERE USER_ID = ? ORDER BY ROWID`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying authorities: %w", err)
	}
	defer rows.Close()

	var authorities []model.Authority
	for rows.Next() {
		var authority model.Authority
		if err := rows.Scan(&authority.Name); err != nil {
			return nil, fmt.Errorf("scanning authority: %w", err)
		}
		authorities = append(authorities, authority)
	}
	return authorities, rows.Err()
}

// AuthorityRepository reads authorities. The original declares the matching
// JpaRepository but no application code calls it; it is kept so the data model
// stays complete.
type AuthorityRepository struct {
	db *sql.DB
}

// NewAuthorityRepository returns a repository backed by db.
func NewAuthorityRepository(db *sql.DB) *AuthorityRepository { return &AuthorityRepository{db: db} }

// FindAll returns every authority, ordered by name as JpaRepository#findAll
// would return them from a single-column primary-key table.
func (r *AuthorityRepository) FindAll(ctx context.Context) ([]model.Authority, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT NAME FROM AUTHORITY ORDER BY NAME`)
	if err != nil {
		return nil, fmt.Errorf("querying authorities: %w", err)
	}
	defer rows.Close()

	var authorities []model.Authority
	for rows.Next() {
		var authority model.Authority
		if err := rows.Scan(&authority.Name); err != nil {
			return nil, fmt.Errorf("scanning authority: %w", err)
		}
		authorities = append(authorities, authority)
	}
	return authorities, rows.Err()
}
