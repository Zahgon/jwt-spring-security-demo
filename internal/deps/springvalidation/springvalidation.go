// Package springvalidation reproduces the JSON shape Spring MVC renders for a
// MethodArgumentNotValidException — the "errors" array that appears in a 400
// response when a @Valid @RequestBody fails Bean Validation.
//
// Only the two constraints the original's LoginDto carries are modelled:
// @NotNull and @Size. Each one contributes a FieldError whose "codes" and
// "arguments" are built the way Spring's DefaultMessageCodesResolver and
// SpringValidatorAdapter build them, because those arrays are part of the
// response body and not merely internal bookkeeping.
package springvalidation

import "strconv"

// FieldError is org.springframework.validation.FieldError as Jackson serialises
// it. Field order here is the order Jackson emits, and is therefore significant.
type FieldError struct {
	Codes          []string `json:"codes"`
	Arguments      []any    `json:"arguments"`
	DefaultMessage string   `json:"defaultMessage"`
	ObjectName     string   `json:"objectName"`
	Field          string   `json:"field"`
	RejectedValue  any      `json:"rejectedValue"`
	BindingFailure bool     `json:"bindingFailure"`
	Code           string   `json:"code"`
}

// resolvable is DefaultMessageSourceResolvable, the first entry of every
// FieldError's "arguments" array. Its own "arguments" member is always null.
type resolvable struct {
	Codes          []string `json:"codes"`
	Arguments      []any    `json:"arguments"`
	DefaultMessage string   `json:"defaultMessage"`
	Code           string   `json:"code"`
}

// Constraint is one Bean Validation annotation on one field.
type Constraint interface {
	// violated reports whether value breaks the constraint. value is nil when
	// the member was absent from the request body.
	violated(value any) bool
	// name is the annotation's simple name, e.g. "Size".
	name() string
	// message is the constraint's default message.
	message() string
	// extraArguments are appended after the resolvable field name.
	extraArguments() []any
}

// Field describes one validated property of the request object.
type Field struct {
	Name string
	// TypeName is the fully-qualified Java type the original declared, e.g.
	// "java.lang.String". It appears verbatim in the third message code.
	TypeName string
	// Value is the submitted value, or nil when the member was absent.
	Value any
	// Constraints are evaluated in order; the first violation on a field wins,
	// which is how a single annotation per field ends up reported.
	Constraints []Constraint
}

// Validate returns one FieldError per violated constraint. Fields are visited
// in the order given.
//
// The original's order within this array comes from a java.util.HashSet of
// constraint violations and is not stable across constraint types; it is
// documented as not contractual. This implementation reports errors in field
// declaration order.
func Validate(objectName string, fields []Field) []FieldError {
	var errors []FieldError
	for _, field := range fields {
		for _, constraint := range field.Constraints {
			if !constraint.violated(field.Value) {
				continue
			}
			errors = append(errors, newFieldError(objectName, field, constraint))
			break
		}
	}
	return errors
}

func newFieldError(objectName string, field Field, constraint Constraint) FieldError {
	name := constraint.name()
	fieldCodes := []string{objectName + "." + field.Name, field.Name}

	arguments := []any{resolvable{
		Codes:          fieldCodes,
		DefaultMessage: field.Name,
		Code:           field.Name,
	}}
	arguments = append(arguments, constraint.extraArguments()...)

	return FieldError{
		Codes: []string{
			name + "." + objectName + "." + field.Name,
			name + "." + field.Name,
			name + "." + field.TypeName,
			name,
		},
		Arguments:      arguments,
		DefaultMessage: constraint.message(),
		ObjectName:     objectName,
		Field:          field.Name,
		RejectedValue:  field.Value,
		BindingFailure: false,
		Code:           name,
	}
}

// NotNull is javax.validation.constraints.NotNull.
func NotNull() Constraint { return notNull{} }

type notNull struct{}

func (notNull) violated(value any) bool { return value == nil }
func (notNull) name() string            { return "NotNull" }
func (notNull) message() string         { return "must not be null" }
func (notNull) extraArguments() []any   { return nil }

// Size is javax.validation.constraints.Size over a string.
func Size(min, max int) Constraint { return size{min: min, max: max} }

type size struct{ min, max int }

func (s size) violated(value any) bool {
	str, ok := value.(string)
	if !ok {
		// A null value is left to @NotNull; @Size accepts it.
		return false
	}
	return len(str) < s.min || len(str) > s.max
}

func (size) name() string { return "Size" }

func (s size) message() string {
	return "size must be between " + strconv.Itoa(s.min) + " and " + strconv.Itoa(s.max)
}

// Spring appends the constraint's attributes in descending alphabetical order
// of attribute name, which for @Size puts max before min.
func (s size) extraArguments() []any { return []any{s.max, s.min} }
