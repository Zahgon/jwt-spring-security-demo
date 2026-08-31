// Package jackson reproduces the JSON layout that Jackson's
// DefaultPrettyPrinter emits when Spring Boot turns on
// SerializationFeature.INDENT_OUTPUT, which the original application does via
// "spring.jackson.serialization.INDENT_OUTPUT: true".
//
// The layout is not the one encoding/json produces, and the difference is
// visible in every response body:
//
//   - objects break across lines with a two-space indent per nesting level;
//   - the separator between a field name and its value is " : ", with a space
//     on both sides of the colon;
//   - arrays are *not* broken across lines. Jackson's default array indenter is
//     FixedSpaceIndenter, so an array is written "[", a space, the elements
//     separated by ", ", a space, "]". Because that indenter is "inline",
//     entering an array does not increase the indent level — an object nested
//     inside an array is indented relative to the object that holds the array.
//   - an empty object or array is written "{ }" / "[ ]";
//   - Jackson does not escape '<', '>' or '&'.
package jackson

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Marshal encodes v as JSON in Jackson's DefaultPrettyPrinter layout. The
// output has no trailing newline, matching what Jackson writes to a response
// body.
func Marshal(v any) ([]byte, error) {
	compact, err := marshalCompact(v)
	if err != nil {
		return nil, err
	}
	return Indent(compact)
}

// Indent re-formats already-encoded JSON into Jackson's layout. Object member
// order is taken from the input, so encoding a Go struct with Marshal keeps the
// struct's field order.
func Indent(src []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var out bytes.Buffer
	if err := writeValue(&out, dec, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// EncodeString encodes s as a JSON string literal without Go's HTML escaping,
// matching how Jackson writes string values.
func EncodeString(s string) []byte {
	b, err := marshalCompact(s)
	if err != nil { // unreachable: a string always encodes
		panic(err)
	}
	return b
}

func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// depth is the number of enclosing objects. Arrays do not contribute to it,
// because Jackson's array indenter is inline.
func writeValue(out *bytes.Buffer, dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return writeScalar(out, tok)
	}
	switch delim {
	case '{':
		return writeObject(out, dec, depth)
	case '[':
		return writeArray(out, dec, depth)
	default:
		return fmt.Errorf("jackson: unexpected delimiter %q", delim)
	}
}

func writeObject(out *bytes.Buffer, dec *json.Decoder, depth int) error {
	out.WriteByte('{')
	entries := 0
	for dec.More() {
		if entries > 0 {
			out.WriteByte(',')
		}
		writeNewlineIndent(out, depth+1)
		name, err := dec.Token()
		if err != nil {
			return err
		}
		if err := writeScalar(out, name); err != nil {
			return err
		}
		out.WriteString(" : ")
		if err := writeValue(out, dec, depth+1); err != nil {
			return err
		}
		entries++
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return err
	}
	if entries > 0 {
		writeNewlineIndent(out, depth)
	} else {
		out.WriteByte(' ')
	}
	out.WriteByte('}')
	return nil
}

func writeArray(out *bytes.Buffer, dec *json.Decoder, depth int) error {
	out.WriteByte('[')
	entries := 0
	for dec.More() {
		if entries == 0 {
			out.WriteByte(' ')
		} else {
			out.WriteString(", ")
		}
		if err := writeValue(out, dec, depth); err != nil {
			return err
		}
		entries++
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return err
	}
	out.WriteString(" ]")
	return nil
}

func writeScalar(out *bytes.Buffer, tok json.Token) error {
	switch v := tok.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		out.WriteString(v.String())
	case string:
		out.Write(EncodeString(v))
	default:
		return fmt.Errorf("jackson: unexpected token %T", tok)
	}
	return nil
}

func writeNewlineIndent(out *bytes.Buffer, depth int) {
	out.WriteByte('\n')
	for i := 0; i < depth; i++ {
		out.WriteString("  ")
	}
}
