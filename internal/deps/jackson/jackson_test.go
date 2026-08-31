package jackson_test

import (
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/jackson"
)

// The layout below is what Spring Boot's INDENT_OUTPUT setting produces. The
// original delegated it entirely to Jackson, so it had no tests of its own.

func TestMarshalLayout(t *testing.T) {
	type authority struct {
		Name string `json:"name"`
	}
	type user struct {
		Username    string      `json:"username"`
		Authorities []authority `json:"authorities"`
	}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "object members are separated by a space on both sides of the colon",
			value: map[string]string{"message": "this is a hidden message!"},
			want:  "{\n  \"message\" : \"this is a hidden message!\"\n}",
		},
		{
			name:  "arrays stay inline and do not deepen the indent",
			value: user{Username: "admin", Authorities: []authority{{Name: "ROLE_USER"}, {Name: "ROLE_ADMIN"}}},
			want: "{\n" +
				"  \"username\" : \"admin\",\n" +
				"  \"authorities\" : [ {\n" +
				"    \"name\" : \"ROLE_USER\"\n" +
				"  }, {\n" +
				"    \"name\" : \"ROLE_ADMIN\"\n" +
				"  } ]\n" +
				"}",
		},
		{
			name:  "an empty array is a bracket pair around one space",
			value: map[string][]string{"authorities": {}},
			want:  "{\n  \"authorities\" : [ ]\n}",
		},
		{
			name:  "an empty object is a brace pair around one space",
			value: map[string]map[string]string{"page": {}},
			want:  "{\n  \"page\" : { }\n}",
		},
		{
			name:  "scalars of every kind round-trip",
			value: map[string]any{"n": nil},
			want:  "{\n  \"n\" : null\n}",
		},
		{
			name:  "HTML characters are not escaped",
			value: map[string]string{"message": "a<b>c&d"},
			want:  "{\n  \"message\" : \"a<b>c&d\"\n}",
		},
		{
			name:  "arrays of scalars are comma-space separated",
			value: map[string][]int{"codes": {1, 2, 3}},
			want:  "{\n  \"codes\" : [ 1, 2, 3 ]\n}",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := jackson.Marshal(test.value)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(got) != test.want {
				t.Errorf("Marshal() =\n%s\nwant\n%s", got, test.want)
			}
		})
	}
}

func TestMarshalHasNoTrailingNewline(t *testing.T) {
	got, err := jackson.Marshal(map[string]int{"status": 401})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got[len(got)-1] != '}' {
		t.Errorf("Marshal() = %q; want it to end at the closing brace", got)
	}
}

func TestEncodeStringDoesNotEscapeHTML(t *testing.T) {
	if got := string(jackson.EncodeString("a<b")); got != `"a<b"` {
		t.Errorf("EncodeString() = %s, want %s", got, `"a<b"`)
	}
}
