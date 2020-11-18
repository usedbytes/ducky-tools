// SPDX-License-Identifier: MIT
// Copyright (c) 2020 Brian Starkey <stark3y@gmail.com>
package xor

import (
	"bytes"
	"sort"

	"github.com/pkg/errors"
	"github.com/usedbytes/log"
)

func chunk(data []byte, chunkLen int, chunk int) []byte {
	return data[chunkLen * chunk:chunkLen * (chunk + 1)]
}

func heuristicFindKey(data []byte, keylen int) ([]byte, error) {
	if keylen != 52 {
		return nil, errors.New("only keylen 52 is supported for heuristic search")
	}

	counts := [52][256]int{}

	// Count occurrence
	for i := 0; i < len(data); i += 52 {
		for j := 0; j < 52 && i+j < len(data); j++ {
			val := data[i+j]
			counts[j][val] = counts[j][val] + 1
		}
	}

	// Find max occurrence
	maxVals := [52]byte{}
	for i, val := range counts {
		maxVal := 0
		maxIdx := 0
		for j, v := range val {
			if v > maxVal {
				maxVal = v
				maxIdx = j
			}
		}
		maxVals[i] = byte(maxIdx)
	}

	// Expect the last couple of chunks to be zeroes (not guaranteed)
	idx := ((len(data) / 52) - 1) * 52
	a := data[idx:idx+52]
	b := data[idx+52:]
	key := [52]byte{}
	fixedUp := false

	for i := 0; i < 52; i++ {
		// TODO: This could be smarter.
		if maxVals[i] != a[i] {
			fixedUp = true
			log.Verbosef("maxVal[%d] (%d) != a[%d] (%d) %d\n", i, maxVals[i], i, a[i], len(b))
			if i < len(b) {
				if a[i] == b[i] {
					key[i] = a[i]
					log.Verbosef("Using a[%d] (%d)\n", i, a[i])
				} else if maxVals[i] == b[i] {
					log.Verbosef("Keeping maxVals[%d] (%d), matches b[%d]\n", i, maxVals[i], i)
					key[i] = maxVals[i]
				} else {
					log.Verbosef("Keeping maxVals[%d] (%d), all different: %d %d %d\n",
							i, maxVals[i], maxVals[i], a[i], b[i])
					key[i] = maxVals[i]
				}
			} else {
				countA := counts[i][a[i]]

				// Sorting destroys the indexing, so need to make a copy
				sorted := append([]int(nil), counts[i][:]...)
				sort.Ints(sorted)
				idx := sort.SearchInts(sorted, countA)
				if idx > 250 {
					log.Verbosef("Using a[%d] (%d), sorted at position %d\n", i, a[i], 256 - idx)
					key[i] = a[i]
				} else {
					log.Verbosef("Keeping maxVals[%d] (%d), a[%d] sorted at position %d\n",
							i, maxVals[i], i, a[i], 256 - idx)
					key[i] = maxVals[i]
				}
			}
		} else {
			key[i] = maxVals[i]
		}
	}

	if fixedUp {
		log.Println("WARNING: Some values were ambiguous")
	}

	return key[:], nil
}

func FindKey(data []byte, keylen int) ([]byte, error) {
	var candidate []byte

	// Look for consecutive chunks that are identical
	// They're probably zeroes.
	// They _could be_ 0xff, which is "erased flash" value, but in the
	// examples I've seen, padding is zeroes.
	var i int
	fullChunks := len(data) / keylen
	for i = 0; i < fullChunks - 1; i++ {
		a := chunk(data, keylen, i)
		b := chunk(data, keylen, i + 1)
		if bytes.Compare(a, b) == 0 {
			candidate = a
			break
		}
	}

	if candidate == nil {
		log.Println("WARNING: Simple key search failed, falling back to heuristics. This may well be incorrect!")
		return heuristicFindKey(data, keylen)
	}

	numMatches := 2

	// Now check how many others there are that are the same
	for ; i < fullChunks - 1; i++ {
		b := chunk(data, keylen, i + 1)
		if bytes.Compare(candidate, b) == 0 {
			numMatches++
		}
	}

	log.Verbosef("Found %d chunks with this value.\n", numMatches)

	return candidate, nil
}
