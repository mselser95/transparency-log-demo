// txl-verify -- an OFFLINE verifier for Rekor transparency-log entries.
//
// It takes files. It opens no sockets. Everything it needs -- the entry, the
// inclusion proof, the signed checkpoint, the log's public key, the artifact
// itself -- is on disk before it starts, and the whole point is that the
// answer it gives does not depend on the log being honest, reachable, or the
// same log that answered a moment ago.
//
//	txl-verify inclusion   --entry E --artifact A --log-pubkey K [--signer-pubkey S]
//	                       [--anchor signed-checkpoint|response-roothash]
//	txl-verify consistency --proof P --first N --first-checkpoint C1
//	                       --second M --second-checkpoint C2 --log-pubkey K
//
// Exit 0 only if every check passed. Exit 1 naming the checks that did not.
//
// Sources:
//   Newman, Meyers & Torres-Arias, "Sigstore: Software Signing for Everybody",
//     ACM CCS 2022, pp. 2353-2367. DOI 10.1145/3548606.3560596.
//   Laurie, Langley & Kasper, "Certificate Transparency", RFC 6962, 2013.
//   Merkle, "A Digital Signature Based on a Conventional Encryption Function",
//     CRYPTO '87, LNCS 293, pp. 369-378.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---- reporting -------------------------------------------------------------

type reporter struct {
	n      int
	failed []string
}

func (r *reporter) check(name string, err error, okDetail string) {
	r.n++
	if err != nil {
		r.failed = append(r.failed, name)
		fmt.Printf("   [%2d] %-22s FAIL  %s\n", r.n, name, err.Error())
		return
	}
	fmt.Printf("   [%2d] %-22s PASS  %s\n", r.n, name, okDetail)
}

func (r *reporter) skip(name, why string) {
	r.n++
	fmt.Printf("   [%2d] %-22s SKIP  %s\n", r.n, name, why)
}

func (r *reporter) finish(what string) {
	if len(r.failed) == 0 {
		fmt.Printf("   VERDICT %s: VERIFIED  (%d checks, 0 failed)\n", what, r.n)
		os.Exit(0)
	}
	fmt.Printf("   VERDICT %s: REFUSED   (%d checks, %d failed: %s)\n",
		what, r.n, len(r.failed), strings.Join(r.failed, ", "))
	os.Exit(1)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "txl-verify: "+format+"\n", a...)
	os.Exit(2)
}

// ---- rekor wire shapes -----------------------------------------------------

type rekorEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

type hashedRekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// ---- the note (checkpoint) format ------------------------------------------
//
// A Rekor checkpoint is a signed note:
//
//	<origin>\n<tree size>\n<base64 root hash>\n[optional lines]\n
//	\n
//	— <key name> <base64( 4-byte key hint || signature )>\n
//
// The signed bytes are the TEXT ONLY, up to and including the newline that
// ends the last text line -- not the blank separator and not the signature
// lines. Getting that boundary wrong produces a verifier that rejects every
// genuine checkpoint, which is the failure people fix by disabling the check.

type checkpoint struct {
	text     string
	origin   string
	treeSize uint64
	root     [32]byte
	keyName  string
	keyHint  [4]byte
	sig      []byte
}

func parseCheckpoint(s string) (*checkpoint, error) {
	if s == "" {
		return nil, errors.New("the entry carries no checkpoint, so there is no signed root to anchor anything to")
	}
	i := strings.Index(s, "\n\n")
	if i < 0 {
		return nil, errors.New("malformed note: no blank line separating text from signatures")
	}
	cp := &checkpoint{text: s[:i+1]}
	lines := strings.Split(strings.TrimSuffix(cp.text, "\n"), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("malformed note: %d text lines, need at least 3", len(lines))
	}
	cp.origin = lines[0]
	n, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed note: tree size %q: %v", lines[1], err)
	}
	cp.treeSize = n
	raw, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("malformed note: root hash line %q is not 32 base64 bytes", lines[2])
	}
	copy(cp.root[:], raw)

	sigBlock := strings.TrimSuffix(s[i+2:], "\n")
	for _, l := range strings.Split(sigBlock, "\n") {
		if !strings.HasPrefix(l, "— ") {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(f[2])
		if err != nil || len(b) < 5 {
			continue
		}
		cp.keyName = f[1]
		copy(cp.keyHint[:], b[:4])
		cp.sig = b[4:]
		return cp, nil
	}
	return nil, errors.New("the note carries no signature line: an UNSIGNED checkpoint is a claim, not a commitment")
}

// ---- crypto helpers --------------------------------------------------------

func loadPublicKeyPEM(path string) (any, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return parsePublicKeyPEM(b)
}

func parsePublicKeyPEM(b []byte) (any, []byte, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, nil, errors.New("not a PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, nil, err
	}
	return k, der, nil
}

func verifySig(pub any, msg, sig []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, d[:], sig) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return errors.New("Ed25519 signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

// ---- inclusion -------------------------------------------------------------

func cmdInclusion(args []string) {
	fs := flag.NewFlagSet("inclusion", flag.ExitOnError)
	entryPath := fs.String("entry", "", "JSON as returned by GET /api/v1/log/entries")
	artifactPath := fs.String("artifact", "", "the artifact the entry is supposed to be about")
	logKeyPath := fs.String("log-pubkey", "", "PEM public key of the transparency log")
	signerKeyPath := fs.String("signer-pubkey", "", "PEM public key the artifact was signed with (optional)")
	anchor := fs.String("anchor", "signed-checkpoint",
		"what the recomputed root is compared against: signed-checkpoint (correct) or response-roothash (the control)")
	_ = fs.Parse(args)
	if *entryPath == "" || *artifactPath == "" || *logKeyPath == "" {
		die("inclusion needs --entry, --artifact and --log-pubkey")
	}
	if *anchor != "signed-checkpoint" && *anchor != "response-roothash" {
		die("--anchor must be signed-checkpoint or response-roothash, got %q", *anchor)
	}

	r := &reporter{}

	// [1] There is an entry at all.
	//
	// This is the check that the `never-uploaded` control fails, and it is the
	// one people assume is covered by "we sign everything". A signature over a
	// blob that was never logged verifies perfectly and says nothing about
	// when it was made or whether anyone else can ever see that it exists.
	raw, err := os.ReadFile(*entryPath)
	if err != nil {
		die("cannot read --entry %s: %v", *entryPath, err)
	}
	var byUUID map[string]rekorEntry
	if err := json.Unmarshal(raw, &byUUID); err != nil {
		die("cannot parse --entry %s as a Rekor entry map: %v", *entryPath, err)
	}
	var uuid string
	var e rekorEntry
	switch len(byUUID) {
	case 1:
		for k, v := range byUUID {
			uuid, e = k, v
		}
		r.check("log-entry-present", nil, fmt.Sprintf("1 entry, uuid %s", uuid))
	default:
		r.check("log-entry-present",
			fmt.Errorf("the log holds %d entries for this artifact; a signature alone carries no timestamp and no witness", len(byUUID)), "")
		r.finish("INCLUSION")
	}

	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		die("entry body is not base64: %v", err)
	}
	var hr hashedRekord
	if err := json.Unmarshal(body, &hr); err != nil {
		die("entry body is not a Rekor record: %v", err)
	}

	// [2] The entry is ABOUT this artifact. Without this, every check below is
	// a correct proof about somebody else's bytes.
	art, err := os.ReadFile(*artifactPath)
	if err != nil {
		die("cannot read --artifact %s: %v", *artifactPath, err)
	}
	sum := sha256.Sum256(art)
	artHex := hex.EncodeToString(sum[:])
	if hr.Spec.Data.Hash.Algorithm != "sha256" {
		r.check("artifact-binding", fmt.Errorf("entry hashes with %q, not sha256", hr.Spec.Data.Hash.Algorithm), "")
	} else if hr.Spec.Data.Hash.Value != artHex {
		r.check("artifact-binding", fmt.Errorf("entry is about sha256:%s, the artifact on disk is sha256:%s",
			hr.Spec.Data.Hash.Value, artHex), "")
	} else {
		r.check("artifact-binding", nil, "entry names sha256:"+artHex[:16]+"... = the artifact on disk")
	}

	// [3] The signature inside the entry really is over this artifact, made by
	// the key the entry names.
	sigBytes, err1 := base64.StdEncoding.DecodeString(hr.Spec.Signature.Content)
	keyPEM, err2 := base64.StdEncoding.DecodeString(hr.Spec.Signature.PublicKey.Content)
	switch {
	case err1 != nil || err2 != nil:
		r.check("entry-signature", errors.New("signature or public key in the entry is not base64"), "")
	default:
		pub, der, err := parsePublicKeyPEM(keyPEM)
		if err != nil {
			r.check("entry-signature", fmt.Errorf("public key in the entry: %v", err), "")
		} else if err := verifySig(pub, art, sigBytes); err != nil {
			r.check("entry-signature", err, "")
		} else {
			kh := sha256.Sum256(der)
			r.check("entry-signature", nil, "verifies over the artifact, signer key sha256:"+hex.EncodeToString(kh[:4]))
		}
	}

	// [3b] ...and that key is the one we expected, if the caller said so.
	if *signerKeyPath != "" {
		_, wantDER, err := loadPublicKeyPEM(*signerKeyPath)
		if err != nil {
			r.check("expected-signer", err, "")
		} else {
			_, gotDER, err2 := parsePublicKeyPEM(keyPEM)
			if err2 != nil {
				r.check("expected-signer", err2, "")
			} else if sha256.Sum256(wantDER) != sha256.Sum256(gotDER) {
				r.check("expected-signer", errors.New("the entry was signed by a DIFFERENT key than --signer-pubkey"), "")
			} else {
				r.check("expected-signer", nil, "the entry's signer key is the expected one")
			}
		}
	}

	// [4] The leaf. Rekor's leaf value is the canonicalised entry body, so the
	// leaf hash is SHA-256(0x00 || body) -- and the second half of the entry
	// UUID IS that leaf hash, which makes the entry's own name a checkable
	// value rather than an opaque handle.
	leaf := LeafHash(body)
	leafHex := hex.EncodeToString(leaf[:])
	if len(uuid) >= 64 && strings.HasSuffix(uuid, leafHex) {
		r.check("leaf-hash", nil, "SHA-256(0x00||body) = "+leafHex[:24]+"... = the uuid suffix")
	} else {
		r.check("leaf-hash", fmt.Errorf("SHA-256(0x00||body) = %s but the uuid is %s -- the body was altered after it was logged",
			leafHex, uuid), "")
	}

	// [5] The RFC 6962 audit path, recomputed here rather than trusted.
	ip := e.Verification.InclusionProof
	path := make([][32]byte, 0, len(ip.Hashes))
	pathOK := true
	for _, h := range ip.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			pathOK = false
			break
		}
		var n [32]byte
		copy(n[:], b)
		path = append(path, n)
	}
	var recomputed [32]byte
	if !pathOK {
		r.check("merkle-path", errors.New("a hash in the audit path is not 32 hex bytes"), "")
	} else if ip.TreeSize <= 0 {
		r.check("merkle-path", fmt.Errorf("tree size %d", ip.TreeSize), "")
	} else {
		recomputed, err = RootFromInclusionProof(leaf, uint64(ip.LogIndex), uint64(ip.TreeSize), path)
		if err != nil {
			r.check("merkle-path", err, "")
		} else {
			r.check("merkle-path", nil, fmt.Sprintf("%d sibling hash(es), index %d of tree size %d -> root %s...",
				len(path), ip.LogIndex, ip.TreeSize, hex.EncodeToString(recomputed[:])[:24]))
		}
	}

	cp, cpErr := parseCheckpoint(ip.Checkpoint)

	// [6] THE ANCHOR. What the recomputed root is compared against.
	//
	// `signed-checkpoint` compares it against the root inside the note the log
	// SIGNED. `response-roothash` compares it against the rootHash field of
	// the same JSON document the path came from -- which is arithmetically
	// correct, self-consistent, and proves nothing at all, because whoever
	// produced the path also produced the root it reconciles to. That mode
	// exists so the demo can execute the failure rather than describe it.
	switch *anchor {
	case "response-roothash":
		want, derr := hex.DecodeString(ip.RootHash)
		if derr != nil || len(want) != 32 {
			r.check("root-anchor", errors.New("rootHash in the response is not 32 hex bytes"), "")
		} else if !bytesEqual(recomputed[:], want) {
			r.check("root-anchor", fmt.Errorf("recomputed %x, response says %x", recomputed, want), "")
		} else {
			r.check("root-anchor", nil, "recomputed root == the rootHash field OF THE SAME RESPONSE (self-consistent; anchored to nothing)")
		}
		r.skip("checkpoint-signature", "--anchor=response-roothash never looks at the signed checkpoint")
		r.skip("log-identity", "--anchor=response-roothash never looks at the signed checkpoint")
		r.skip("signed-entry-timestamp", "--anchor=response-roothash never looks at the log's signature")
	default:
		if cpErr != nil {
			r.check("root-anchor", cpErr, "")
		} else if cp.root != recomputed {
			r.check("root-anchor", fmt.Errorf("recomputed %x, the SIGNED checkpoint commits to %x", recomputed, cp.root), "")
		} else if cp.treeSize != uint64(ip.TreeSize) {
			r.check("root-anchor", fmt.Errorf("checkpoint is for tree size %d, the proof is for %d", cp.treeSize, ip.TreeSize), "")
		} else {
			r.check("root-anchor", nil, "recomputed root == the root the log SIGNED, at tree size "+strconv.FormatUint(cp.treeSize, 10))
		}

		// [7] The checkpoint's signature.
		logKey, logDER, kerr := loadPublicKeyPEM(*logKeyPath)
		if kerr != nil {
			die("cannot read --log-pubkey %s: %v", *logKeyPath, kerr)
		}
		if cpErr != nil {
			r.check("checkpoint-signature", errors.New("no checkpoint to verify"), "")
			r.check("log-identity", errors.New("no checkpoint to verify"), "")
		} else {
			if err := verifySig(logKey, []byte(cp.text), cp.sig); err != nil {
				r.check("checkpoint-signature", err, "")
			} else {
				r.check("checkpoint-signature", nil, "note signed by the log, origin "+cp.origin)
			}
			// [8] ...by THAT log. The note's 4-byte key hint is the first four
			// bytes of SHA-256 over the DER public key, which is also the
			// prefix of Rekor's logID. A checkpoint signed by a key that
			// verifies is only useful if it is the key you were told to expect.
			kh := sha256.Sum256(logDER)
			switch {
			case !bytesEqual(kh[:4], cp.keyHint[:]):
				r.check("log-identity", fmt.Errorf("note key hint %x does not match SHA-256(log public key)[:4] = %x",
					cp.keyHint, kh[:4]), "")
			case e.LogID != "" && hex.EncodeToString(kh[:]) != e.LogID:
				r.check("log-identity", fmt.Errorf("SHA-256(log public key) = %s but the entry claims logID %s",
					hex.EncodeToString(kh[:]), e.LogID), "")
			default:
				r.check("log-identity", nil, "key hint "+hex.EncodeToString(cp.keyHint[:])+" = SHA-256(log key)[:4] = logID prefix")
			}
		}

		// [9] THE TIMESTAMP. This is the check that makes the whole exercise
		// worth doing: the Signed Entry Timestamp is the log's signature over
		// {body, integratedTime, logID, logIndex}. Without it `integratedTime`
		// is a number in a JSON document that anyone can edit. With it, WHEN
		// is a signed fact.
		if e.Verification.SignedEntryTimestamp == "" {
			r.check("signed-entry-timestamp", errors.New("absent: integratedTime is then just a number in a JSON document"), "")
		} else {
			setSig, derr := base64.StdEncoding.DecodeString(e.Verification.SignedEntryTimestamp)
			if derr != nil {
				r.check("signed-entry-timestamp", errors.New("not base64"), "")
			} else {
				canon := canonicalSETPayload(e)
				if err := verifySig(logKey, canon, setSig); err != nil {
					r.check("signed-entry-timestamp", err, "")
				} else {
					r.check("signed-entry-timestamp", nil,
						"the log signed integratedTime="+strconv.FormatInt(e.IntegratedTime, 10)+
							" ("+time.Unix(e.IntegratedTime, 0).UTC().Format(time.RFC3339)+")")
				}
			}
		}
	}

	fmt.Println()
	fmt.Printf("   log index          : %d\n", e.LogIndex)
	fmt.Printf("   integrated time    : %d  (%s)\n", e.IntegratedTime,
		time.Unix(e.IntegratedTime, 0).UTC().Format(time.RFC3339))
	fmt.Printf("   tree size at proof : %d\n", ip.TreeSize)
	fmt.Printf("   audit path length  : %d\n", len(ip.Hashes))
	fmt.Printf("   recomputed root    : %s\n", hex.EncodeToString(recomputed[:]))
	if cpErr == nil {
		fmt.Printf("   root the log SIGNED: %s\n", hex.EncodeToString(cp.root[:]))
		fmt.Printf("   checkpoint origin  : %s\n", cp.origin)
	} else {
		fmt.Printf("   root the log SIGNED: <none: %s>\n", cpErr.Error())
	}
	fmt.Printf("   rootHash in response: %s\n", ip.RootHash)
	fmt.Println()
	r.finish("INCLUSION")
}

// canonicalSETPayload reproduces the bytes Rekor signs for the Signed Entry
// Timestamp: RFC 8785 (JCS) canonical JSON over {body, integratedTime, logID,
// logIndex}. For this payload -- four members, ASCII string and integer values
// -- JCS is exactly Go's encoding/json with sorted keys and no whitespace, so
// a hand-built canonicalisation is honest here and only here.
func canonicalSETPayload(e rekorEntry) []byte {
	m := map[string]any{
		"body":           e.Body,
		"integratedTime": e.IntegratedTime,
		"logID":          e.LogID,
		"logIndex":       e.LogIndex,
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	// encoding/json sorts map keys; HTML escaping must be OFF because JCS does
	// not escape < > &. No value in this payload contains one, so this changes
	// nothing today -- and it is exactly the sort of thing that changes when a
	// log's origin string grows a character nobody expected.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		die("canonicalising SET payload: %v", err)
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n"))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- consistency -----------------------------------------------------------

func cmdConsistency(args []string) {
	fs := flag.NewFlagSet("consistency", flag.ExitOnError)
	proofPath := fs.String("proof", "", "JSON as returned by GET /api/v1/log/proof")
	first := fs.Uint64("first", 0, "the earlier tree size")
	second := fs.Uint64("second", 0, "the later tree size")
	cp1Path := fs.String("first-checkpoint", "", "file holding the signed checkpoint at the earlier size")
	cp2Path := fs.String("second-checkpoint", "", "file holding the signed checkpoint at the later size")
	logKeyPath := fs.String("log-pubkey", "", "PEM public key of the transparency log")
	_ = fs.Parse(args)
	if *proofPath == "" || *cp1Path == "" || *cp2Path == "" || *logKeyPath == "" || *first == 0 || *second == 0 {
		die("consistency needs --proof --first --second --first-checkpoint --second-checkpoint --log-pubkey")
	}

	r := &reporter{}
	logKey, logDER, err := loadPublicKeyPEM(*logKeyPath)
	if err != nil {
		die("cannot read --log-pubkey: %v", err)
	}
	kh := sha256.Sum256(logDER)

	load := func(path string, want uint64, label string) *checkpoint {
		b, err := os.ReadFile(path)
		if err != nil {
			die("cannot read %s: %v", path, err)
		}
		cp, err := parseCheckpoint(string(b))
		if err != nil {
			r.check(label+"-checkpoint", err, "")
			return nil
		}
		switch {
		case verifySig(logKey, []byte(cp.text), cp.sig) != nil:
			r.check(label+"-checkpoint", errors.New("signature does not verify with the log's public key"), "")
			return nil
		case !bytesEqual(kh[:4], cp.keyHint[:]):
			r.check(label+"-checkpoint", fmt.Errorf("signed by a different key (hint %x, expected %x)", cp.keyHint, kh[:4]), "")
			return nil
		case cp.treeSize != want:
			r.check(label+"-checkpoint", fmt.Errorf("is for tree size %d, not %d", cp.treeSize, want), "")
			return nil
		}
		r.check(label+"-checkpoint", nil, fmt.Sprintf("signed by the log, size %d, root %s...",
			cp.treeSize, hex.EncodeToString(cp.root[:])[:24]))
		return cp
	}

	cp1 := load(*cp1Path, *first, "earlier")
	cp2 := load(*cp2Path, *second, "later")
	if cp1 == nil || cp2 == nil {
		r.finish("CONSISTENCY")
	}

	var pf struct {
		Hashes   []string `json:"hashes"`
		RootHash string   `json:"rootHash"`
	}
	b, err := os.ReadFile(*proofPath)
	if err != nil {
		die("cannot read --proof: %v", err)
	}
	if err := json.Unmarshal(b, &pf); err != nil {
		die("cannot parse --proof: %v", err)
	}
	nodes := make([][32]byte, 0, len(pf.Hashes))
	for _, h := range pf.Hashes {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			die("proof node %q is not 32 hex bytes", h)
		}
		var n [32]byte
		copy(n[:], raw)
		nodes = append(nodes, n)
	}

	err = VerifyConsistency(*first, *second, nodes, cp1.root, cp2.root)
	if err != nil {
		r.check("append-only", err, "")
	} else {
		r.check("append-only", nil, fmt.Sprintf("%d node(s) prove size %d is a prefix of size %d",
			len(nodes), *first, *second))
	}

	fmt.Println()
	fmt.Printf("   earlier size %-4d root (signed): %s\n", *first, hex.EncodeToString(cp1.root[:]))
	fmt.Printf("   later   size %-4d root (signed): %s\n", *second, hex.EncodeToString(cp2.root[:]))
	fmt.Printf("   consistency proof nodes       : %d\n", len(nodes))
	fmt.Println()
	r.finish("CONSISTENCY")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: txl-verify inclusion|consistency [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "inclusion":
		cmdInclusion(os.Args[2:])
	case "consistency":
		cmdConsistency(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}
