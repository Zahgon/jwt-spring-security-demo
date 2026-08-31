// Package hibernatevalidator reproduces the parts of Hibernate Validator that
// the original application observes directly rather than through Bean
// Validation annotations.
//
// UserModelDetailsService instantiates EmailValidator by hand and uses it to
// decide which column to look an account up by: a login that passes the email
// test is matched against EMAIL case-insensitively, anything else is lowercased
// and matched against USERNAME. That decision is visible in the error message a
// failed login returns, so the exact rule matters and not merely "does it look
// like an email".
package hibernatevalidator

import (
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxLocalPartLength  = 64
	maxDomainPartLength = 255
)

// The patterns below are transcriptions of AbstractEmailValidator and
// DomainNameUtil from Hibernate Validator 6.0, the version Spring Boot 2.1.8
// resolves. They are anchored here because Java's Matcher#matches anchors
// implicitly.
var (
	localPartPattern = regexp.MustCompile(`(?i)^(?:` + localPartAtom + `+|"` + localPartInsideQuotesAtom + `+")(?:\.(?:` + localPartAtom + `+|"` + localPartInsideQuotesAtom + `+"))*$`)
	domainPattern    = regexp.MustCompile(`(?i)^(?:` + domain + `|` + ipDomain + `|` + ipV6Domain + `)$`)
)

const (
	localPartAtom             = "[a-z0-9!#$%&'*+/=?^_`{|}~\\x{0080}-\\x{FFFF}-]"
	localPartInsideQuotesAtom = "(?:[a-z0-9!#$%&'*.(),<>\\[\\]:;@+/=?^_`{|}~\\x{0080}-\\x{FFFF} -]|\\\\|\\\")"

	domainCharsWithoutDash = "[a-z\\x{0080}-\\x{FFFF}0-9!#$%&'*+/=?^_`{|}~]"
	domainLabel            = "(?:" + domainCharsWithoutDash + "-*)*" + domainCharsWithoutDash + "+"
	domain                 = domainLabel + "(?:\\." + domainLabel + ")*"
	ipDomain               = `\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]`
	ipV6Domain             = `\[(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|::|(?:[0-9A-Fa-f]{1,4}:)+:(?:[0-9A-Fa-f]{1,4}:?)*)\]`
)

// IsValidEmail reports whether value satisfies Hibernate Validator's @Email
// rule. As in the original, the empty string is accepted — @Email only
// constrains the shape of a value that is present, and @NotNull/@Size are what
// reject absent or empty ones.
func IsValidEmail(value string) bool {
	if len(value) == 0 {
		return true
	}

	split := lastUnquotedAt(value)
	if split < 0 {
		return false
	}
	localPart, domainPart := value[:split], value[split+1:]

	if !isValidLocalPart(localPart) {
		return false
	}
	return isValidDomain(domainPart)
}

// lastUnquotedAt finds the '@' that separates local part from domain, ignoring
// any that sit inside a quoted local part or an IPv6 literal.
func lastUnquotedAt(value string) int {
	split := -1
	quoted := false
	inIPv6 := false
	for i, r := range value {
		switch {
		case r == '"':
			quoted = !quoted
		case r == '[' && !quoted:
			inIPv6 = true
		case r == ']' && !quoted:
			inIPv6 = false
		case r == '@' && !quoted && !inIPv6:
			split = i
		}
	}
	return split
}

func isValidLocalPart(localPart string) bool {
	if len(localPart) > maxLocalPartLength {
		return false
	}
	return localPartPattern.MatchString(localPart)
}

func isValidDomain(domainPart string) bool {
	if strings.HasSuffix(domainPart, ".") {
		return false
	}
	if !domainPattern.MatchString(domainPart) {
		return false
	}
	ascii, err := idna.ToASCII(domainPart)
	if err != nil {
		return false
	}
	return len(ascii) <= maxDomainPartLength
}
