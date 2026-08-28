// txl-verify-stub -- a DELIBERATELY VACUOUS verifier.
//
// It accepts the same flags as txl-verify, prints lines that look exactly like
// a successful verification, and exits 0 without opening a single file.
//
// It exists for one reason: `TXL_CONTROL=self-check` substitutes it for the
// real verifier and re-runs the whole demo's battery of assertions. If the
// demo still reports success, then every PASS the validated run prints is a
// green light wired to nothing -- the run would be proving that a program was
// invoked, not that an artifact is in a log. The self-check run therefore
// requires the demo to CATCH this binary, and says how many of the demo's
// assertions caught it.
//
// This is the constructive form of the vacuity argument: substitute `return 0`
// and show that the gate notices. Asserting that a check is load-bearing is
// not the same as demonstrating it.
package main

import (
	"fmt"
	"os"
)

func main() {
	sub := "inclusion"
	if len(os.Args) > 1 {
		sub = os.Args[1]
	}
	fmt.Println("   [ 1] log-entry-present      PASS  1 entry, uuid <not read>")
	fmt.Println("   [ 2] artifact-binding       PASS  <not read>")
	fmt.Println("   [ 3] entry-signature        PASS  <not read>")
	fmt.Println("   [ 4] leaf-hash              PASS  <not computed>")
	fmt.Println("   [ 5] merkle-path            PASS  <not computed>")
	fmt.Println("   [ 6] root-anchor            PASS  <not compared>")
	fmt.Println("   [ 7] checkpoint-signature   PASS  <not verified>")
	fmt.Println("   [ 8] log-identity           PASS  <not verified>")
	fmt.Println("   [ 9] signed-entry-timestamp PASS  <not verified>")
	fmt.Println()
	fmt.Println("   log index          : 0")
	fmt.Println("   integrated time    : 0  (1970-01-01T00:00:00Z)")
	fmt.Println("   recomputed root    : 0000000000000000000000000000000000000000000000000000000000000000")
	fmt.Println("   root the log SIGNED: 0000000000000000000000000000000000000000000000000000000000000000")
	fmt.Println()
	switch sub {
	case "consistency":
		fmt.Println("   VERDICT CONSISTENCY: VERIFIED  (3 checks, 0 failed)")
	default:
		fmt.Println("   VERDICT INCLUSION: VERIFIED  (9 checks, 0 failed)")
	}
	os.Exit(0)
}
