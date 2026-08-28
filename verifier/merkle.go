package main

// RFC 6962 Merkle tree arithmetic, implemented from the specification text.
//
//   Laurie, B., Langley, A. & Kasper, E., "Certificate Transparency",
//   RFC 6962, IETF, June 2013. DOI 10.17487/RFC6962.
//   Section 2.1 defines the Merkle Tree Hash (MTH); 2.1.1 the audit
//   (inclusion) path; 2.1.2 the consistency proof.
//
// The construction is Merkle's:
//
//   Merkle, R. C., "A Digital Signature Based on a Conventional Encryption
//   Function", CRYPTO '87, LNCS 293, pp. 369-378. DOI 10.1007/3-540-48184-2_32.
//
// Nothing here talks to the log. That is the entire point: an inclusion proof
// is only worth something if the party relying on it does this arithmetic
// ITSELF. Asking the log "is my entry included?" and believing the answer is
// not a proof, it is a promise.
//
// The two domain-separation prefixes are load-bearing and are not decoration.
// Without them a leaf whose bytes happen to be the concatenation of two node
// hashes could be presented as an interior node, and a second preimage for the
// root becomes constructible. RFC 6962 2.1: leaves are hashed with a 0x00
// prefix, interior nodes with 0x01.

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// LeafHash is MTH({d(0)}) = SHA-256(0x00 || d(0)).
func LeafHash(b []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash is SHA-256(0x01 || left || right).
func NodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// EmptyRootHash is MTH({}) = SHA-256() -- the hash of the empty string. A log
// that has never been written to publishes this, and it is worth printing once
// so that "the tree is empty" is a value a reader can check rather than a
// claim the log makes about itself.
func EmptyRootHash() [32]byte {
	return sha256.Sum256(nil)
}

// RootFromInclusionProof recomputes the Merkle Tree Hash of a tree of `size`
// leaves from ONE leaf hash, that leaf's index, and the audit path. RFC 6962
// 2.1.1, in the iterative form RFC 9162 2.1.3.2 writes out.
//
// It returns the root the caller must then compare against a root the LOG
// SIGNED. Returning the root rather than a boolean is deliberate: a verifier
// that returns bool invites the caller to hand it the root the log just sent
// in the same response, which is arithmetic that always succeeds and proves
// nothing. See the `unanchored-root` control in run-demo.sh.
//
// Both loop branches carry real cases and both are exercised by the tests:
// `fn` odd means this leaf is a RIGHT child so the sibling goes on the left;
// `fn == sn` is the ragged right-hand edge of a tree whose size is not a power
// of two, where a node is promoted rather than paired.
func RootFromInclusionProof(leaf [32]byte, index, size uint64, path [][32]byte) ([32]byte, error) {
	var zero [32]byte
	if size == 0 {
		return zero, errors.New("tree size is 0: an empty log contains nothing, so no inclusion proof over it can be valid")
	}
	if index >= size {
		return zero, fmt.Errorf("leaf index %d lies outside a tree of size %d", index, size)
	}
	r := leaf
	fn, sn := index, size-1
	for i, p := range path {
		if sn == 0 {
			return zero, fmt.Errorf("audit path has %d hashes but the tree of size %d is exhausted after %d", len(path), size, i)
		}
		if fn%2 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn != 0 && fn%2 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return zero, fmt.Errorf("audit path has only %d hashes; %d level(s) of the tree of size %d were never covered", len(path), sn, size)
	}
	return r, nil
}

// VerifyConsistency checks that a tree of `second` leaves is an APPEND-ONLY
// extension of the tree of `first` leaves -- that every leaf the log committed
// to at the earlier size is still there, at the same index, under the later
// root. RFC 6962 2.1.2.
//
// This is the half of the property that a per-entry inclusion proof cannot
// give you. An inclusion proof says "my entry is under root R". A consistency
// proof says "the root you signed last week is a prefix of the root you signed
// today", which is what makes a log that quietly drops or reorders an entry
// -- or shows two different histories to two different clients -- detectable
// at all.
func VerifyConsistency(first, second uint64, proof [][32]byte, firstRoot, secondRoot [32]byte) error {
	if first > second {
		return fmt.Errorf("first size %d is larger than second size %d", first, second)
	}
	if first == second {
		if len(proof) != 0 {
			return fmt.Errorf("sizes are equal (%d) so the proof must be empty, but it carries %d hash(es)", first, len(proof))
		}
		if firstRoot != secondRoot {
			return fmt.Errorf("sizes are equal (%d) but the roots differ: %x vs %x", first, firstRoot, secondRoot)
		}
		return nil
	}
	if first == 0 {
		// Every tree extends the empty tree; RFC 6962 defines the proof as
		// empty. Accepting this is correct and it is also why a demo must
		// never rest on a first size of 0.
		if len(proof) != 0 {
			return fmt.Errorf("consistency from size 0 needs an empty proof, but it carries %d hash(es)", len(proof))
		}
		return nil
	}
	if len(proof) == 0 {
		return fmt.Errorf("consistency proof from %d to %d is empty", first, second)
	}

	nodes := proof
	// RFC 6962: when `first` is an exact power of two the first node of the
	// path is the earlier root itself, and the log omits it because the
	// verifier already has it. Putting it back is not an optimisation -- a
	// verifier that forgets it silently rejects every consistency proof whose
	// first size is a power of two, which is most of them.
	if first&(first-1) == 0 {
		nodes = append([][32]byte{firstRoot}, proof...)
	}

	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := nodes[0], nodes[0]
	for i, c := range nodes[1:] {
		if sn == 0 {
			return fmt.Errorf("consistency proof has %d nodes but the tree of size %d is exhausted after %d", len(nodes), second, i+1)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("consistency proof has only %d nodes; %d level(s) were never covered", len(nodes), sn)
	}
	if fr != firstRoot {
		return fmt.Errorf("the proof reconstructs %x as the root at size %d, but the log signed %x -- history was rewritten", fr, first, firstRoot)
	}
	if sr != secondRoot {
		return fmt.Errorf("the proof reconstructs %x as the root at size %d, but the log signed %x", sr, second, secondRoot)
	}
	return nil
}
