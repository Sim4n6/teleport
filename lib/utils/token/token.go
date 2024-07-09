/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package token

import (
	"math"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/defaults"
)

// Verify ensures the token fits into our length requirements and
// its bits of entropy are sufficient.
func Verify(token []byte) error {
	return verify(token, defaults.MaxTokenLength)
}

// VerifyHashed ensures the token fits into our length requirements and
// its bits of entropy are sufficient. If the token is not going to be
// hashed by bcrypt before it will be used, use [Verify] instead.
func VerifyHashed(token []byte) error {
	return verify(token, defaults.MaxHashedTokenLength)
}

func verify(token []byte, maxLen int) error {
	if len(token) < defaults.MinTokenLength {
		return trace.BadParameter("token is too short, min length is %d", defaults.MinTokenLength)
	}
	if len(token) > maxLen {
		return trace.BadParameter("token is too long, max length is %d", maxLen)
	}

	entropyBits := EntropyBits(token)
	if entropyBits < defaults.MinTokenEntropyBits {
		return trace.BadParameter("token is not random enough, only has %d bits of entropy; min bits of entropy is %d", entropyBits, defaults.MinTokenEntropyBits)
	}

	return nil
}

// EntropyBits computes the number of bits of entropy the input has
// using the formula E = log2(RL) where E is bits of entropy, R is
// the range of different characters in the input, and L is the length
// of the input.
func EntropyBits(input []byte) int {
	freq := make(map[byte]struct{})
	for _, b := range input {
		freq[b] = struct{}{}
	}

	r := float64(len(freq))
	l := float64(len(input))

	return int(
		math.Round(
			math.Log2(
				math.Pow(r, l))))
}
