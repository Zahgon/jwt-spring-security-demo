package hibernatevalidator_test

import (
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/hibernatevalidator"
)

// The rule matters because it decides which column a login is looked up by, and
// so which of two differently-worded errors a failed login reports.
func TestIsValidEmail(t *testing.T) {
	tests := map[string]bool{
		// The three seeded accounts' logins.
		"admin":             false,
		"user":              false,
		"disabled":          false,
		"admin@admin.com":   true,
		"enabled@user.com":  true,
		"disabled@user.com": true,

		// Other logins the endpoint sees.
		"not_existing":  false,
		"USER":          false,
		"nope@nope.com": true,

		// Shape rules.
		"":                  true, // @Email accepts an absent value; @NotNull and @Size reject it
		"@example.com":      false,
		"user@":             false,
		"user@example.":     false,
		"user@localhost":    true,
		"first.last@ex.com": true,
		"user name@ex.com":  false,
		"user@@example.com": false,
		"user@[127.0.0.1]":  true,
	}

	for input, want := range tests {
		if got := hibernatevalidator.IsValidEmail(input); got != want {
			t.Errorf("IsValidEmail(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIsValidEmailRejectsAnOverlongLocalPart(t *testing.T) {
	local := ""
	for i := 0; i < 65; i++ {
		local += "a"
	}

	if hibernatevalidator.IsValidEmail(local + "@example.com") {
		t.Error("IsValidEmail() accepted a local part longer than 64 characters")
	}
}
