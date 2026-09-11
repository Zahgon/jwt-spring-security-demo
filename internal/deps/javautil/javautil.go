// Package javautil reproduces the two pieces of java.util behaviour that leak
// into the original application's HTTP responses.
//
// The entity User holds its authorities in a java.util.HashSet, and Jackson
// serialises that set in the set's own iteration order. For the "admin" account
// that order is ROLE_USER, ROLE_ADMIN — neither alphabetical nor the insertion
// order of the seed data — so it cannot be reproduced by sorting. It falls out
// of the way HashMap buckets String hash codes, which is what this package
// computes.
package javautil

import (
	"sort"
	"unicode/utf16"
)

// StringHashCode returns java.lang.String#hashCode: s[0]*31^(n-1) + s[1]*31^(n-2)
// + ... + s[n-1], evaluated over UTF-16 code units in 32-bit signed arithmetic.
func StringHashCode(s string) int32 {
	var h int32
	for _, unit := range utf16.Encode([]rune(s)) {
		h = 31*h + int32(unit)
	}
	return h
}

// ObjectsHash returns java.util.Objects#hash for elements whose hash codes are
// given: Arrays.hashCode over a one-element array is 31*1 + element.
func ObjectsHash(hashes ...int32) int32 {
	result := int32(1)
	for _, h := range hashes {
		result = 31*result + h
	}
	return result
}

// HashSetOrder returns elems in the order a java.util.HashSet would iterate
// them, had they been inserted in the given order with the given hash codes.
//
// HashMap places a key in bucket spread(hash) & (capacity-1), where
// spread(h) = h ^ (h >>> 16), and iterates buckets in ascending index order,
// walking each bucket's chain in insertion order. Capacity starts at 16 and
// doubles whenever the size would exceed three quarters of it. Resizing splits
// each chain while preserving relative order, so the final iteration order is
// the same as bucketing every element at the final capacity — that is, a stable
// sort by bucket index. (This holds while chains stay below HashMap's
// treeify threshold of 8, which a handful of authorities never approaches.)
func HashSetOrder[T any](elems []T, hash func(T) int32) []T {
	ordered := make([]T, len(elems))
	copy(ordered, elems)

	capacity := 16
	for len(ordered) > capacity*3/4 {
		capacity <<= 1
	}
	mask := uint32(capacity - 1)

	sort.SliceStable(ordered, func(i, j int) bool {
		return spread(hash(ordered[i]))&mask < spread(hash(ordered[j]))&mask
	})
	return ordered
}

// spread reproduces HashMap#hash: the high 16 bits are XORed down so that they
// take part in the bucket index.
func spread(h int32) uint32 {
	u := uint32(h)
	return u ^ (u >> 16)
}
