package javautil_test

import (
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/javautil"
)

func TestStringHashCode(t *testing.T) {
	// Values taken from java.lang.String#hashCode.
	tests := map[string]int32{
		"":           0,
		"a":          97,
		"ROLE_USER":  -1142751756,
		"ROLE_ADMIN": -1084475866,
	}

	for input, want := range tests {
		if got := javautil.StringHashCode(input); got != want {
			t.Errorf("StringHashCode(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestObjectsHash(t *testing.T) {
	// Objects.hash(name) is 31*1 + name.hashCode().
	if got, want := javautil.ObjectsHash(javautil.StringHashCode("ROLE_USER")), int32(-1142751725); got != want {
		t.Errorf("ObjectsHash(ROLE_USER) = %d, want %d", got, want)
	}
}

// TestHashSetOrderMatchesTheAdminAccount pins the ordering the original's
// /api/user response shows for the admin account: ROLE_USER before ROLE_ADMIN,
// even though the join table inserts ROLE_USER first and ROLE_ADMIN second and
// the alphabetical order is the other way round.
func TestHashSetOrderMatchesTheAdminAccount(t *testing.T) {
	insertionOrder := []string{"ROLE_USER", "ROLE_ADMIN"}

	got := javautil.HashSetOrder(insertionOrder, func(name string) int32 {
		return javautil.ObjectsHash(javautil.StringHashCode(name))
	})

	want := []string{"ROLE_USER", "ROLE_ADMIN"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("HashSetOrder() = %v, want %v", got, want)
	}
}

// TestHashSetOrderIsIndependentOfInsertionOrder shows the ordering is a
// property of the hashes and not of the order the rows arrive in.
func TestHashSetOrderIsIndependentOfInsertionOrder(t *testing.T) {
	hash := func(name string) int32 { return javautil.ObjectsHash(javautil.StringHashCode(name)) }

	forwards := javautil.HashSetOrder([]string{"ROLE_USER", "ROLE_ADMIN"}, hash)
	backwards := javautil.HashSetOrder([]string{"ROLE_ADMIN", "ROLE_USER"}, hash)

	if forwards[0] != backwards[0] || forwards[1] != backwards[1] {
		t.Errorf("order depends on insertion: %v vs %v", forwards, backwards)
	}
}
