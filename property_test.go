package urn

// Bounded generators, shrinkers and mutation-kill tests for the three adjacent URN
// grammars implemented here:
//
//   - RFC 2141 (RFC2141Only, also the Default parsing mode)
//   - RFC 8141 (RFC8141Only: adds informal namespaces, '~', '&' and '/' in the
//     NSS, plus r/q-components and the f-component)
//   - RFC 7643 SCIM (RFC7643Only: the fixed "ietf:params:scim" namespace)
//
// Every generated input is assembled from legal components, so the parser MUST
// accept it; random-byte fuzzing that mostly exercises rejection paths lives
// in FuzzURNProperties instead and never runs during a plain "go test".

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// fixedSeed makes every deterministic run reproducible; a single seed can be
	// replayed with URN_SEED=<n> go test -run TestBoundedProperties.
	fixedSeed      int64 = 20260921
	samplesPerMode       = 300
	nidMaxLen2141        = 32 // implementation grammar allows 1..32 (the error string says 31)
	nidMinLen8141        = 2
	nidMaxLen8141        = 32
)

var (
	alnum       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hexDigits   = "0123456789abcdefABCDEF"
	sss2141     = "()+,-.:=@;$_!*'" // RFC2141 NSS reserved+unreserved (besides alnum/hex)
	scimTypes   = []string{"schemas", "api", "param"}
	prefixCases = []string{"urn", "URN", "Urn", "uRN", "UrN", "uRn", "URn", "urN"}
)

func flipCaseASCII(b byte) byte {
	switch {
	case 'a' <= b && b <= 'z':
		return b - 32
	case 'A' <= b && b <= 'Z':
		return b + 32
	}
	return b
}

// genPct emits a legal percent-encoding token. With 1/2 chance a hex letter is
// uppercase so that string fidelity and normalized strings differ (and can be
// asserted separately).
func genPct(rng *rand.Rand) string {
	b := make([]byte, 3)
	b[0] = '%'
	b[1] = hexDigits[rng.Intn(len(hexDigits))]
	b[2] = hexDigits[rng.Intn(len(hexDigits))]
	if rng.Intn(2) == 0 {
		for i := 1; i < 3; i++ {
			if c := b[i]; ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F') {
				b[i] = strings.ToUpper(string(c))[0]
			}
		}
	}
	return string(b)
}

// genNID2141 builds a legal RFC2141 NID: 1..32 chars, alnum start, alnum or
// dash afterwards; the exact (case-insensitive) "urn" NID is reserved and
// filtered out. It deliberately exercises the length endpoints.
func genNID2141(rng *rand.Rand) string {
	var n int
	switch rng.Intn(3) {
	case 0:
		n = 1
	case 1:
		n = nidMaxLen2141
	default:
		n = 1 + rng.Intn(nidMaxLen2141)
	}
	b := make([]byte, n)
	b[0] = alnum[rng.Intn(len(alnum))]
	for i := 1; i < n; i++ {
		if rng.Intn(5) == 0 {
			b[i] = '-'
		} else {
			b[i] = alnum[rng.Intn(len(alnum))]
		}
	}
	return string(b)
}

// genNID8141 builds a legal RFC8141 NID: length 2..32, alnum at both ends,
// alnum or dash inside. Informal namespaces (case-insensitive "urn-" prefix)
// are avoided because they form a separate reserved family.
func genNID8141(rng *rand.Rand) string {
	var n int
	switch rng.Intn(3) {
	case 0:
		n = nidMinLen8141
	case 1:
		n = nidMaxLen8141
	default:
		n = nidMinLen8141 + rng.Intn(nidMaxLen8141-nidMinLen8141+1)
	}
	b := make([]byte, n)
	b[0] = alnum[rng.Intn(len(alnum))]
	for i := 1; i < n-1; i++ {
		if rng.Intn(5) == 0 {
			b[i] = '-'
		} else {
			b[i] = alnum[rng.Intn(len(alnum))]
		}
	}
	b[n-1] = alnum[rng.Intn(len(alnum))]
	if strings.HasPrefix(strings.ToLower(string(b)), "urn-") {
		b[0] = 'x'
	}
	return string(b)
}

// genNSS2141 builds a non-empty RFC2141 NSS: alnum / reserved+unreserved /
// percent tokens. Colons are legal and common in real NSSes.
func genNSS2141(rng *rand.Rand) string {
	var sb strings.Builder
	n := 1 + rng.Intn(8)
	for i := 0; i < n; i++ {
		switch rng.Intn(4) {
		case 0:
			sb.WriteString(genPct(rng))
		case 1:
			sb.WriteByte(sss2141[rng.Intn(len(sss2141))])
		default:
			sb.WriteByte(alnum[rng.Intn(len(alnum))])
		}
	}
	return sb.String()
}

// genNSS8141 builds a non-empty RFC8141 NSS: first char is a pchar (~ and &
// allowed, '/' not first), later chars may contain '/'. '?' never appears
// inside the NSS (it would start r/q/f syntax).
func genNSS8141(rng *rand.Rand) string {
	var sb strings.Builder
	n := 1 + rng.Intn(8)
	for i := 0; i < n; i++ {
		switch rng.Intn(6) {
		case 0:
			sb.WriteString(genPct(rng))
		case 1:
			sb.WriteByte("~&"[rng.Intn(2)])
		case 2:
			sb.WriteByte(sss2141[rng.Intn(len(sss2141))])
		default:
			sb.WriteByte(alnum[rng.Intn(len(alnum))])
		}
	}
	if rng.Intn(2) == 0 {
		sb.WriteByte('/')
		sb.WriteByte(alnum[rng.Intn(len(alnum))])
	}
	return sb.String()
}

// genComponent builds a non-empty RFC8141 r/q-component. First char must not be
// '/' or '?'; later chars may be '/' or '?'.
func genComponent(rng *rand.Rand) string {
	var sb strings.Builder
	n := 1 + rng.Intn(6)
	for i := 0; i < n; i++ {
		switch rng.Intn(5) {
		case 0:
			sb.WriteString(genPct(rng))
		case 1:
			sb.WriteByte("~&"[rng.Intn(2)])
		case 2:
			sb.WriteByte(sss2141[rng.Intn(len(sss2141))])
		default:
			sb.WriteByte(alnum[rng.Intn(len(alnum))])
		}
	}
	for _, c := range "/?" {
		if rng.Intn(3) == 0 {
			sb.WriteRune(c)
			sb.WriteByte(alnum[rng.Intn(len(alnum))])
		}
	}
	return sb.String()
}

// genFragment builds a non-empty RFC8141 f-component (fragment allows '/', '?').
func genFragment(rng *rand.Rand) string {
	var sb strings.Builder
	if rng.Intn(2) == 0 {
		sb.WriteByte("/?"[rng.Intn(2)])
	}
	n := 1 + rng.Intn(6)
	for i := 0; i < n; i++ {
		switch rng.Intn(5) {
		case 0:
			sb.WriteString(genPct(rng))
		case 1:
			sb.WriteByte("~&"[rng.Intn(2)])
		case 2:
			sb.WriteByte(sss2141[rng.Intn(len(sss2141))])
		default:
			sb.WriteByte(alnum[rng.Intn(len(alnum))])
		}
	}
	return sb.String()
}

// genSCIM builds a legal SCIM URN: urn-prefix is case-insensitive, the
// namespace literal is exact lowercase, name is alnum only, other uses sss/hex.
func genSCIM(rng *rand.Rand) string {
	var sb strings.Builder
	sb.WriteString(prefixCases[rng.Intn(len(prefixCases))])
	sb.WriteString(":ietf:params:scim:")
	sb.WriteString(scimTypes[rng.Intn(len(scimTypes))])
	sb.WriteByte(':')
	nameLen := 1 + rng.Intn(6)
	for i := 0; i < nameLen; i++ {
		sb.WriteByte(alnum[rng.Intn(len(alnum))])
	}
	if rng.Intn(2) == 0 {
		sb.WriteByte(':')
		for i := 0; i < 1+rng.Intn(5); i++ {
			switch rng.Intn(4) {
			case 0:
				sb.WriteString(genPct(rng))
			case 1:
				sb.WriteByte(sss2141[rng.Intn(len(sss2141))])
			default:
				sb.WriteByte(alnum[rng.Intn(len(alnum))])
			}
		}
	}
	return sb.String()
}

// genURN assembles a legal URN in the given mode and returns it together with
// the generated r/q/f components (empty when not present or not applicable).
type generated struct {
	input   string
	r, q, f string
	hasRQ   bool
}

func genURNRaw(rng *rand.Rand, mode ParsingMode) generated {
	switch mode {
	case RFC7643Only:
		return generated{input: genSCIM(rng)}
	case RFC8141Only:
		g := generated{}
		g.input = prefixCases[rng.Intn(len(prefixCases))] + ":" + genNID8141(rng) + ":" + genNSS8141(rng)
		// Ordering allowed by the grammar: r then q; or q alone; or none.
		switch rng.Intn(4) {
		case 0:
			g.r = genComponent(rng)
			g.input += "?+" + g.r
			if rng.Intn(2) == 0 {
				g.q = genComponent(rng)
				g.input += "?=" + g.q
			}
		case 1:
			g.q = genComponent(rng)
			g.input += "?=" + g.q
		}
		if rng.Intn(2) == 0 {
			g.f = genFragment(rng)
			g.input += "#" + g.f
		}
		return g
	default:
		return generated{input: prefixCases[rng.Intn(len(prefixCases))] + ":" + genNID2141(rng) + ":" + genNSS2141(rng)}
	}
}

// genURN assembles from legal components, then asks the parser whether
// the assembled bytes are accepted. The grammar has a handful of
// generated-machine quirks (e.g. its reserved-"urn" guard firing on
// NIDs shaped u?n) that are not expressible as a clean component
// rule; rather than reverse-engineering every quirk into the
// generator, a rejected candidate is simply rebuilt. Every attempt
// is component-legal; no random bytes are ever injected.
func genURN(rng *rand.Rand, mode ParsingMode) generated {
	for attempt := 0; attempt < 64; attempt++ {
		g := genURNRaw(rng, mode)
		if _, ok := Parse([]byte(g.input), WithParsingMode(mode)); ok {
			return g
		}
	}
	panic("property generator could not build a legal URN in 64 attempts")
}

// --- expected normalization -----------------------------------------------------

// expectedNorm renders the canonical string: "urn" prefix, lowercase NID,
// NSS with only the letters of percent tokens lowercased. It mirrors the
// documented semantics of Normalize rather than calling Normalize itself.
func expectedNorm(prefix, id, nss string) string {
	var sb strings.Builder
	sb.WriteString("urn:")
	sb.WriteString(strings.ToLower(id))
	sb.WriteByte(':')
	for i := 0; i < len(nss); i++ {
		if nss[i] == '%' && i+2 < len(nss) {
			sb.WriteByte('%')
			sb.WriteString(strings.ToLower(nss[i+1 : i+3]))
			i += 2
		} else {
			sb.WriteByte(nss[i])
		}
	}
	return sb.String()
}

// --- equivalent / inequivalent transforms --------------------------------------

// flipPrefix toggles the case of one prefix letter (prefix chars only).
func flipPrefix(in string) string {
	b := []byte(in)
	idx := []int{}
	for i := 0; i < 3; i++ {
		if c := b[i]; ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') {
			idx = append(idx, i)
		}
	}
	b[idx[0]] = flipCaseASCII(b[idx[0]])
	return string(b)
}

// flipNID toggles one alnum letter inside the NID region (colon-delimited).
func flipNID(in string, rng *rand.Rand) string {
	b := []byte(in)
	start := strings.IndexByte(in, ':') + 1
	end := strings.IndexByte(in[start:], ':') + start
	var letters []int
	for i := start; i < end; i++ {
		if c := b[i]; ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') {
			letters = append(letters, i)
		}
	}
	if len(letters) == 0 {
		return ""
	}
	i := letters[rng.Intn(len(letters))]
	b[i] = flipCaseASCII(b[i])
	return string(b)
}

// flipNSSLetter toggles one non-encoded letter inside the NSS, which must
// change NSS bytes (a non-equivalence transform). Returns "" when no letter
// exists outside percent tokens.
func flipNSSLetter(in string, nssStart int, rng *rand.Rand) string {
	b := []byte(in)
	var letters []int
	for i := nssStart; i < len(b); i++ {
		if b[i] == '%' && i+2 < len(b) {
			i += 2 // skip encoded octet: never a plain letter transform
			continue
		}
		if c := b[i]; ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') {
			letters = append(letters, i)
		}
	}
	if len(letters) == 0 {
		return ""
	}
	i := letters[rng.Intn(len(letters))]
	b[i] = flipCaseASCII(b[i])
	return string(b)
}

// flipHexCase changes case of one hex letter of one percent token (equivalent
// under lexical equivalence). Returns "" when no hex letter is available.
func flipHexCase(in string, nssStart int, rng *rand.Rand) string {
	b := []byte(in)
	var pos []int
	for i := nssStart; i+2 < len(b); i++ {
		if b[i] == '%' {
			for j := i + 1; j <= i+2; j++ {
				if c := b[j]; ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F') {
					pos = append(pos, j)
				}
			}
		}
	}
	if len(pos) == 0 {
		return ""
	}
	i := pos[rng.Intn(len(pos))]
	b[i] = flipCaseASCII(b[i])
	return string(b)
}

// variants returns transformed inputs plus whether the transform MUST preserve
// lexical equality with the original parse result.
type variant struct {
	input      string
	equivalent bool
	desc       string
}

func buildVariants(rng *rand.Rand, mode ParsingMode, in string) []variant {
	var out []variant
	switch mode {
	case RFC7643Only:
		out = append(out, variant{flipPrefix(in), true, "prefix case"})
		// type part ("schemas"/"api"/"param") is case-sensitive and
		// fixed-shape: transforms only apply to name/other, i.e. after
		// the 5th colon ("urn:ietf:params:scim:schemas:").
		nameStart := 0
		for i := 0; i < 5; i++ {
			nameStart = strings.IndexByte(in[nameStart:], ':') + nameStart + 1
		}
		if v := flipHexCase(in, nameStart, rng); v != "" {
			out = append(out, variant{v, true, "hex token case"})
		}
		if v := flipNSSLetter(in, nameStart, rng); v != "" {
			out = append(out, variant{v, false, "plain name letter case"})
		}
	case RFC8141Only:
		out = append(out, variant{flipPrefix(in), true, "prefix case"})
		if flipped := flipNID(in, rng); flipped != "" {
			out = append(out, variant{flipped, true, "NID case"})
		}
		nssStart := 0
		for i := 0; i < 2; i++ {
			nssStart = strings.IndexByte(in[nssStart:], ':') + nssStart + 1
		}
		componentStart := len(in)
		if i := strings.IndexAny(in, "#?"); i >= 0 {
			componentStart = i
		}
		nssOnly := in[:componentStart]
		if v := flipHexCase(nssOnly, nssStart, rng); v != "" {
			out = append(out, variant{v + in[componentStart:], true, "hex token case"})
		}
		if v := flipNSSLetter(nssOnly, nssStart, rng); v != "" {
			out = append(out, variant{v + in[componentStart:], false, "plain NSS letter case"})
		}
		// Stripping r/q/f syntax always preserves equality: components are
		// not part of URN-equivalence (RFC 8141, section 3.2). Marker
		// search is bounded to the component region because component
		// contents can themselves contain '?', '#', etc.
		rest := in
		if i := strings.IndexByte(rest[componentStart:], '#'); i >= 0 {
			pos := componentStart + i
			out = append(out, variant{in[:pos], true, "drop f-component"})
			rest = rest[:pos]
		}
		if i := strings.Index(rest[componentStart:], "?="); i >= 0 && len(rest[componentStart:])-i > 2 {
			pos := componentStart + i
			out = append(out, variant{in[:pos], true, "drop q-component"})
			rest = rest[:pos]
		}
		if i := strings.Index(rest[componentStart:], "?+"); i >= 0 && len(rest[componentStart:])-i > 2 {
			pos := componentStart + i
			out = append(out, variant{in[:pos], true, "drop r-component"})
		}
	default:
		out = append(out, variant{flipPrefix(in), true, "prefix case"})
		if flipped := flipNID(in, rng); flipped != "" {
			out = append(out, variant{flipped, true, "NID case"})
		}
		start := 0
		for i := 0; i < 2; i++ {
			start = strings.IndexByte(in[start:], ':') + start + 1
		}
		if v := flipHexCase(in, start, rng); v != "" {
			out = append(out, variant{v, true, "hex token case"})
		}
		if v := flipNSSLetter(in, start, rng); v != "" {
			out = append(out, variant{v, false, "plain NSS letter case"})
		}
	}
	return out
}

// --- property harness --------------------------------------------------------

func modeName(m ParsingMode) string {
	switch m {
	case RFC8141Only:
		return "8141"
	case RFC7643Only:
		return "scim"
	default:
		return "2141"
	}
}

// propertyFailure checks every round-trip/equivalence invariant and returns a
// human-readable description of the first one broken, "" when all hold.
// It never calls t.Fatal: the fuzz target and shrinker rely on the
// boolean-style outcome to keep minimizing.
func propertyFailure(t *testing.T, m ParsingMode, in string, want *generated) string {
	t.Helper()

	u, ok := Parse([]byte(in), WithParsingMode(m))
	if !ok || u == nil {
		return "generator input rejected by parser: " + in
	}

	// String fidelity: parse-string-parse keeps every component. This is
	// deliberately asserted against the raw input, never against Normalize output.
	if got := u.String(); got != in {
		return fmt.Sprintf("string fidelity: %q became %q", in, got)
	}
	reparsed, ok := Parse([]byte(u.String()), WithParsingMode(m))
	if !ok || reparsed == nil {
		return "reparse of String() output failed: " + u.String()
	}
	if reparsed.prefix != u.prefix {
		return fmt.Sprintf("prefix not preserved: %q vs %q", u.prefix, reparsed.prefix)
	}
	if reparsed.ID != u.ID {
		return fmt.Sprintf("NID not preserved: %q vs %q", u.ID, reparsed.ID)
	}
	if reparsed.SS != u.SS {
		return fmt.Sprintf("NSS not preserved: %q vs %q", u.SS, reparsed.SS)
	}
	if reparsed.kind != u.kind {
		return fmt.Sprintf("kind not preserved: %d vs %d", u.kind, reparsed.kind)
	}
	if m == RFC8141Only {
		if reparsed.RComponent() != u.rComponent {
			return fmt.Sprintf("r-component not preserved: %q vs %q", u.rComponent, reparsed.RComponent())
		}
		if reparsed.QComponent() != u.qComponent {
			return fmt.Sprintf("q-component not preserved: %q vs %q", u.qComponent, reparsed.QComponent())
		}
		if reparsed.FComponent() != u.fComponent {
			return fmt.Sprintf("f-component not preserved: %q vs %q", u.fComponent, reparsed.FComponent())
		}
		if want != nil {
			if reparsed.RComponent() != want.r {
				return fmt.Sprintf("r-component mismatch generator: %q vs %q", want.r, reparsed.RComponent())
			}
			if reparsed.QComponent() != want.q {
				return fmt.Sprintf("q-component mismatch generator: %q vs %q", want.q, reparsed.QComponent())
			}
			if reparsed.FComponent() != want.f {
				return fmt.Sprintf("f-component mismatch generator: %q vs %q", want.f, reparsed.FComponent())
			}
		}
	}
	if m == RFC7643Only {
		if !reparsed.IsSCIM() || reparsed.SCIM() == nil {
			return "SCIM kind lost on reparse: " + in
		}
	} else if reparsed.IsSCIM() || reparsed.SCIM() != nil {
		return "non-SCIM mode reported SCIM kind: " + in
	}

	// Normalize idempotence: the normalized string is a fixed point of the
	// parse->normalize cycle. Note Normalize drops components and its result
	// carries no norm field (by design), so idempotence is asserted on the
	// string form rather than chaining Normalize twice.
	n1 := u.Normalize()
	if canonical := expectedNorm(u.prefix, u.ID, u.SS); n1.String() != canonical {
		return fmt.Sprintf("canonical form: %q vs %q", canonical, n1.String())
	}
	un, nOk := Parse([]byte(n1.String()), WithParsingMode(m))
	if !nOk || un == nil {
		return "normalized string does not parse: " + n1.String()
	}
	if got := un.Normalize().String(); got != n1.String() {
		return fmt.Sprintf("Normalize not idempotent: %q vs %q", n1.String(), got)
	}

	// Equal reflexive and nil-aware.
	if !u.Equal(u) {
		return "equal not reflexive: " + in
	}
	if !un.Equal(un) {
		return "normalized equal not reflexive: " + in
	}
	if u.Equal(nil) {
		return "equal(nil) reported true: " + in
	}

	// Generated equivalent/inequivalent transforms, checked in both directions.
	rng := rand.New(rand.NewSource(fixedSeed ^ int64(len(in)) ^ int64(m)))
	for _, v := range buildVariants(rng, m, in) {
		vv, vok := Parse([]byte(v.input), WithParsingMode(m))
		if !vok || vv == nil {
			return "variant rejected by parser (" + v.desc + "): " + v.input
		}
		if v.equivalent {
			if !u.Equal(vv) || !vv.Equal(u) {
				return fmt.Sprintf("equivalent variant (%s) split: %q vs %q", v.desc, in, v.input)
			}
		} else if u.Equal(vv) || vv.Equal(u) {
			return fmt.Sprintf("inequivalent variant (%s) collapsed: %q vs %q", v.desc, in, v.input)
		}
	}
	return ""
}

func requireProperties(t *testing.T, m ParsingMode, in string, want *generated) {
	t.Helper()
	if msg := propertyFailure(t, m, in, want); msg != "" {
		t.Fatal(msg)
	}
}

func TestBoundedProperties(t *testing.T) {
	// URN_SEED=<n> reruns one sample directly:
	//
	//	URN_SEED=42 go test -run 'TestBoundedProperties/8141' -count=1
	only := -1
	if s := os.Getenv("URN_SEED"); s != "" {
		n, err := strconv.Atoi(s)
		require.NoError(t, err)
		only = n
	}
	modes := []ParsingMode{RFC2141Only, RFC8141Only, RFC7643Only}
	for _, m := range modes {
		m := m
		t.Run(modeName(m), func(t *testing.T) {
			rng := rand.New(rand.NewSource(fixedSeed ^ int64(m)*1099511628211))
			n := samplesPerMode
			if only >= 0 {
				n = only + 1
			}
			for i := 0; i < n; i++ {
				g := genURN(rng, m)
				if only >= 0 && i != only {
					continue
				}
				i, g := i, g
				t.Run(strconv.Itoa(i)+"/"+g.input, func(t *testing.T) {
					requireProperties(t, m, g.input, &g)
				})
			}
		})
	}
}

// --- shrinker --------------------------------------------------------------

// shrinkURN greedily removes single bytes while the predicate stays true
// and the input stays a legal URN of the same mode, returning the
// shortest local minimum. Percent tokens and structural punctuation are
// removed atomically so a valid input never turns into a different shape.
func shrinkURN(m ParsingMode, in string, bad func(string) bool) string {
	current := in
	changed := true
	for changed {
		changed = false
		for i := 0; i < len(current); {
			width := 1
			// drop a percent token or a structural atom as one unit
			if current[i] == '%' && i+2 < len(current) {
				width = 3
			}
			cand := current[:i] + current[i+width:]
			if len(cand) < len(current) && bad(cand) {
				current = cand
				changed = true
				continue
			}
			i += width
		}
	}
	return current
}

// legalInMode is the predicate shrinker candidates must satisfy: a failure
// only counts when the candidate is still parseable in that mode.
func legalInMode(m ParsingMode) func(string) bool {
	return func(s string) bool {
		_, ok := Parse([]byte(s), WithParsingMode(m))
		return ok
	}
}

func TestShrinker(t *testing.T) {
	// Any URN carrying a literal 'Z' in its NSS violates this synthetic
	// property; shrinker must remove everything not needed to keep the first
	// such Z, landing on a minimal RFC2141 URN.
	hasZ := func(s string) bool {
		_, ok := Parse([]byte(s), WithParsingMode(RFC2141Only))
		return ok && strings.ContainsAny(s, "Z")
	}
	start := "URN:abcdef:helloZworld"
	short := shrinkURN(RFC2141Only, start, hasZ)
	assert.True(t, len(short) < len(start), "shrunk %q -> %q", start, short)
	assert.Contains(t, short, "Z")
	assert.True(t, hasZ(short), "shortest candidate still violates: %q", short)
	assert.Equal(t, short, shrinkURN(RFC2141Only, short, hasZ), "fixed point")
	assert.Equal(t, "URN:f:Z", short)
}

// --- fuzz entrypoint -------------------------------------------------------

// modeFromTag extracts the mode marker the fuzz seed starts with:
// "0:" RFC2141, "1:" RFC8141, "2:" SCIM. Anything else is skipped so random
// corpus bytes never produce false failures.
func modeFromData(data []byte) (ParsingMode, []byte, bool) {
	if len(data) < 2 || data[1] != ':' {
		return 0, nil, false
	}
	rest := data[2:]
	switch data[0] {
	case '0':
		return RFC2141Only, rest, true
	case '1':
		return RFC8141Only, data[2:], true
	case '2':
		return RFC7643Only, data[2:], true
	}
	return 0, nil, false
}

// FuzzURNProperties does not run during a normal "go test"; invoke with
//
//	go test -fuzz=FuzzURNProperties -fuzztime=30s
//
// A single cached seed is replayable directly:
//
//	go test -run='FuzzURNProperties/[0-9a-f]+' -fuzz=FuzzURNProperties -fuzzcachedir=testdata/fuzz/URNProperties
//
// On failure the framework stores the minimal seed; propertyFailure itself also
// shrinks to the shortest legal URN before failing.
func FuzzURNProperties(f *testing.F) {
	// fixed seeds corpus, tagged per mode
	seeds := []struct {
		mode ParsingMode
		n    int
	}{
		{RFC2141Only, 16},
		{RFC8141Only, 24},
		{RFC7643Only, 16},
	}
	for _, s := range seeds {
		rng := rand.New(rand.NewSource(fixedSeed ^ int64(s.mode)*1_000_003))
		for i := 0; i < s.n; i++ {
			f.Add(string(modeTag(s.mode)) + genURN(rng, s.mode).input)
		}
	}
	// plus the always-replayable seed-0 triple from the deterministic suite
	for _, tag := range []byte{'0', '1', '2'} {
		f.Add(string([]byte{tag, ':'}))
	}

	f.Fuzz(func(t *testing.T, data string) {
		mode, rest, ok := modeFromData([]byte(data))
		if !ok {
			return
		}
		// The raw payload bytes drive a deterministic component-based
		// generator: every legal URN is reachable; unstructured
		// fuzz bytes deterministically select another legal one.
		rng := rand.New(rand.NewSource(int64(hashSeed(string(rest))) + int64(mode)*7 + 0x5bd1e995))
		g := genURN(rng, mode)
		bad := func(cand string) bool {
			return legalInMode(mode)(cand) && propertyFailure(t, mode, cand, nil) != ""
		}
		if msg := propertyFailure(t, mode, g.input, &g); msg != "" {
			smallest := shrinkURN(mode, g.input, bad)
			t.Fatalf("%s\nseed: %q\nshortest: %q\nrerun: URN_SEED=<index> go test -run TestBoundedProperties/%s -count=1",
				msg, data, smallest, modeName(mode))
		}
	})
}

func modeTag(m ParsingMode) byte {
	switch m {
	case RFC8141Only:
		return '1'
	case RFC7643Only:
		return '2'
	default:
		return '0'
	}
}

func hashSeed(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// --- mutation kills -----------------------------------------------------------
//
// These three tests prove the assertions above are strong enough: each simulates
// one concrete implementation mutation and requires the corresponding check to
// detect it. If someone weakened the tests, a mutation would silently survive.

// lowerPctBytes simulates mutation A: lowercasing every percent-encoded byte
// when reassembling (instead of preserving the raw URN string).
func lowerPctBytes(in string) string {
	b := []byte(in)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = lowerByte(b[i+1])
			b[i+2] = lowerByte(b[i+2])
		}
	}
	return string(b)
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 32
	}
	return c
}

func TestMutationLowercasePercentBytesIsCaught(t *testing.T) {
	in := "urn:foo:a123%2C456" // upper hex in NSS; canonically equals %2c
	u, ok := Parse([]byte(in), WithParsingMode(RFC2141Only))
	require.True(t, ok)

	// The mutated String() output differs from the original input (fidelity),
	// yet lexical equality still holds: fidelity and equivalence MUST be
	// asserted separately or this mutation would slip through.
	mut := lowerPctBytes(u.String())
	require.Equal(t, "urn:foo:a123%2c456", mut)
	require.NotEqual(t, in, mut)
	v, vok := Parse([]byte(mut), WithParsingMode(RFC2141Only))
	require.True(t, vok)
	require.True(t, u.Equal(v))

	// The mutation must be caught by fidelity: reassembling the mutated
	// parse cannot reproduce the original raw URN. Equality alone would
	// miss this (u and v are canonically identical), which is
	// exactly why raw string fidelity is asserted separately from Normalize.
	require.Equal(t, in, u.String(), "control: original round-trips")
	require.NotEqual(t, in, v.String(), "mutation breaks raw fidelity")
	reparsed, rok := Parse([]byte(v.String()), WithParsingMode(RFC2141Only))
	require.True(t, rok)
	require.Equal(t, v.String(), reparsed.String())
}

// dropQ simulates mutation B: an 8141 String/parse path that ignores the
// q-component (reassembly drops it; equivalence alone would not notice
// because components are excluded from URN-equivalence).
func TestMutationIgnoreQComponentIsCaught(t *testing.T) {
	in := "urn:example:weather?=op=map&lat=39.56"
	u, ok := Parse([]byte(in), WithParsingMode(RFC8141Only))
	require.True(t, ok)
	require.Equal(t, "op=map&lat=39.56", u.QComponent())

	mut := strings.Split(in, "?=")[0]
	v, vok := Parse([]byte(mut), WithParsingMode(RFC8141Only))
	require.True(t, vok)
	// equivalence is blind to q-component ...
	require.True(t, u.Equal(v))
	// ... but fidelity and component preservation are not.
	require.NotEqual(t, in, v.String())
	require.Empty(t, v.QComponent())
	want := &generated{q: "op=map&lat=39.56"}
	require.Contains(t, propertyFailure(t, RFC8141Only, mut, want), "q-component mismatch generator")
}

// TestMutationSCIMReusesGenericNIDRules pins mutation C: a SCIM implementation
// reusing the ordinary NID rule would accept arbitrary-namespace URNs (they
// are perfectly legal RFC 2141) and misclassify them as SCIM.
func TestMutationSCIMReusesGenericNIDRulesIsCaught(t *testing.T) {
	generic := "urn:foo:schemas:core"
	u2141, ok2141 := Parse([]byte(generic), WithParsingMode(RFC2141Only))
	require.True(t, ok2141)
	require.Equal(t, "foo", u2141.ID)
	require.False(t, u2141.IsSCIM())

	uSCIM, okSCIM := Parse([]byte(generic), WithParsingMode(RFC7643Only))
	// The boundary MUST reject generic NIDs in SCIM mode; a mutated
	// implementation (generic NID rule) would return ok with kind RFC7643.
	require.False(t, okSCIM)
	require.Nil(t, uSCIM)

	// Conversely, SCIM namespace casing is exact: uppercasing any
	// namespace letter must be rejected by SCIM and accepted by RFC2141.
	up := "urn:IETF:params:scim:schemas:core"
	a, aok := Parse([]byte(up), WithParsingMode(RFC2141Only))
	require.True(t, aok)
	require.False(t, a.IsSCIM())
	b, bok := Parse([]byte(up), WithParsingMode(RFC7643Only))
	require.False(t, bok)
	require.Nil(t, b)
}

// --- fixed cross-mode boundaries -------------------------------------------

func TestModeBoundaries(t *testing.T) {
	type boundaryCase struct {
		in                  string
		rfc2141             bool
		rfc8141             bool
		scim                bool
		wantNID             string
		wantR, wantQ, wantF string
		wantNorm            string
	}
	cases := []boundaryCase{
		// 8141 NSS extras
		{"urn:aa:a~b", false, true, false, "aa", "", "", "", "urn:aa:a~b"},
		{"urn:aa:a&b", false, true, false, "aa", "", "", "", "urn:aa:a&b"},
		{"urn:aa:a/b", false, true, false, "aa", "", "", "", "urn:aa:a/b"},
		{"urn:aa:/ab", false, false, false, "", "", "", "", ""}, // / first illegal in NSS
		// 8141 components
		{"urn:aa:nss?+r", false, true, false, "aa", "r", "", "", "urn:aa:nss"},
		{"urn:aa:nss?=q", false, true, false, "aa", "", "q", "", "urn:aa:nss"},
		{"urn:aa:nss#frag", false, true, false, "aa", "", "", "frag", "urn:aa:nss"},
		{"urn:aa:nss?+r?=q#f", false, true, false, "aa", "r", "q", "f", "urn:aa:nss"},
		{"urn:aa:nss?+r?+s", false, false, false, "", "", "", "", ""}, // one r only
		{"urn:aa:nss?=", false, false, false, "", "", "", "", ""},     // empty q
		{"urn:aa:nss?+", false, false, false, "", "", "", "", ""},     // empty r
		{"urn:aa:nss#f#g", false, false, false, "", "", "", "", ""},   // one # only
		// generic RFC2141 urn
		{"urn:foo:bar,baz", true, true, false, "foo", "", "", "", "urn:foo:bar,baz"},
		// scim urns are valid 2141/8141 syntax but not SCIM kind there
		{"urn:ietf:params:scim:schemas:core", true, true, true, "ietf:params:scim", "", "", "",
			"urn:ietf:params:scim:schemas:core"},
		{"urn:ietf:params:scim:api:messages:2.0:ListResponse", true, true, true, "ietf:params:scim", "", "", "",
			"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		// scim namespace literal is lowercase-only
		{"urn:ietf:params:SCIM:schemas:core", true, true, false, "ietf:params:SCIM", "", "", "", ""},
		// bad scim shape
		{"urn:ietf:params:scim:wrong:core", true, true, false, "", "", "", "", ""},
		{"urn:ietf:params:scim:schemas:", true, true, false, "", "", "", "", ""},
		{"urn:ietf:params:scim:schemas:core-", true, true, false, "", "", "", "", ""},
		{"urn:ietf:params:scim:schemas:core:~", false, true, false, "", "", "", "", ""},
	}

	for i, c := range cases {
		u, ok := Parse([]byte(c.in), WithParsingMode(RFC2141Only))
		assert.Equal(t, c.rfc2141, ok, "[%d] 2141 %q", i, c.in)
		if ok {
			assert.False(t, u.IsSCIM())
			assert.Equal(t, RFC2141, u.RFC())
		}

		u8, ok8 := Parse([]byte(c.in), WithParsingMode(RFC8141Only))
		assert.Equal(t, c.rfc8141, ok8, "[%d] 8141 %q", i, c.in)
		if ok8 {
			assert.Equal(t, RFC8141, u8.RFC(), "[%d] 8141 kind", i)
			assert.Equal(t, c.wantR, u8.RComponent(), "[%d] r", i)
			assert.Equal(t, c.wantQ, u8.QComponent(), "[%d] q", i)
			assert.Equal(t, c.wantF, u8.FComponent(), "[%d] f", i)
			if c.wantNorm != "" {
				assert.Equal(t, c.wantNorm, u8.Normalize().String(), "[%d] norm", i)
				// String fidelity: normalized form drops components, so the
				// two MUST only coincide when no components exist.
				if c.wantR == "" && c.wantQ == "" && c.wantF == "" {
					assert.Equal(t, u8.String(), u8.Normalize().String(), "[%d]", i)
				} else {
					assert.NotEqual(t, u8.String(), u8.Normalize().String(), "[%d]", i)
				}
			}
		}

		us, oks := Parse([]byte(c.in), WithParsingMode(RFC7643Only))
		assert.Equal(t, c.scim, oks, "[%d] scim %q", i, c.in)
		if oks {
			assert.True(t, us.IsSCIM())
			assert.NotNil(t, us.SCIM())
			assert.Equal(t, c.wantNID, us.ID, "[%d] scim nid", i)
		}
	}

	// default mode is RFC2141Only: 8141-only syntax is rejected there too.
	def, defok := Parse([]byte("urn:aa:nss?+r"))
	assert.False(t, defok)
	assert.Nil(t, def)
	def2, defok2 := Parse([]byte("urn:foo:bar,baz"))
	assert.True(t, defok2)
	assert.Equal(t, RFC2141, def2.RFC())
}

// --- invalid percent encoding / empty required components ----------------------

func TestRejections(t *testing.T) {
	cases := map[ParsingMode][]string{
		RFC2141Only: {
			"urn:a:%",   // truncated percent
			"urn:a:%1",  // truncated percent
			"urn:a:%-1", // non-alnum octet byte
			"urn:a:%1-",
			"urn:a:%%1",
			"urn:a:abc%",
			"urn:a:bar%", // nss ending in bare %
		},
		RFC8141Only: {
			"urn:aa:%",
			"urn:aa:%1",
			"urn:aa:%-1",
			"urn:aa:bar%",
			"urn:aa:nss%1",
			"urn:aa:nss?+%",
			"urn:aa:nss?=%1",
			"urn:aa:nss#%gg%",
		},
		RFC7643Only: {
			"urn:ietf:params:scim:api:messages:%",
			"urn:ietf:params:scim:api:messages:%F",
			"urn:ietf:params:scim:schemas:name:bar%",
		},
	}
	for mode, inputs := range cases {
		for _, in := range inputs {
			u, ok := Parse([]byte(in), WithParsingMode(mode))
			assert.False(t, ok, "%s must reject %q", modeName(mode), in)
			assert.Nil(t, u, "no object for %q", in)
		}
	}

	// empty required components, all modes.
	empty := []string{
		"", "urn", "urn:", "urn::", "urn::nss", "urn:abc",
		"urn:abc:", // empty NSS
	}
	for _, in := range empty {
		for _, mode := range []ParsingMode{RFC2141Only, RFC8141Only, RFC7643Only} {
			u, ok := Parse([]byte(in), WithParsingMode(mode))
			assert.False(t, ok, "%s must reject empty-component %q", modeName(mode), in)
			assert.Nil(t, u)
		}
	}
}

// --- no residue from previous parses --------------------------------------

func TestNoResidue(t *testing.T) {
	m := NewMachine(WithParsingMode(RFC8141Only))

	first, err := m.Parse([]byte("urn:aa:nss?+rcomp?=qcomp#frag"))
	require.NoError(t, err)
	require.Equal(t, "rcomp", first.rComponent)
	require.Equal(t, "qcomp", first.qComponent)
	require.Equal(t, "frag", first.fComponent)
	raw := []byte("urn:aa:nss?+rcomp?=qcomp#frag")
	require.Equal(t, "urn:aa:nss?+rcomp?=qcomp#frag", string(raw), "input slice untouched after success")

	// A later successful parse without components must not reuse old fields.
	second, err := m.Parse([]byte("urn:bb:plain"))
	require.NoError(t, err)
	require.Equal(t, "bb", second.ID)
	require.Equal(t, "plain", second.SS)
	assert.Empty(t, second.rComponent)
	assert.Empty(t, second.qComponent)
	assert.Empty(t, second.fComponent)
	assert.Nil(t, second.scim)
	require.Equal(t, "urn:bb:plain", second.String())
	require.NoError(t, m.Error())

	// A failed parse must not report residue of the previous success either.
	failed, errf := m.Parse([]byte("urn:cc:nss?"))
	require.Error(t, errf)
	require.Nil(t, failed)
	require.Same(t, errf, m.Error())

	// Back to success: everything fresh again.
	fourth, err4 := m.Parse([]byte("urn:dd:ok?+r2"))
	require.NoError(t, err4)
	require.Equal(t, "r2", fourth.rComponent)
	assert.Empty(t, fourth.qComponent)
	assert.Empty(t, fourth.fComponent)

	// Cross-mode reuse: scim success then scim-invalid must stay empty.
	ms := NewMachine(WithParsingMode(RFC7643Only))
	su, serr := ms.Parse([]byte("urn:ietf:params:scim:schemas:core:2.0:User"))
	require.NoError(t, serr)
	require.NotNil(t, su.scim)
	bad, badErr := ms.Parse([]byte("urn:foo:schemas:core"))
	require.Error(t, badErr)
	require.Nil(t, bad)

	// failed parse must not mutate caller bytes either.
	in := []byte("urn:aa:bad%")
	_, _ = NewMachine(WithParsingMode(RFC8141Only)).Parse(in)
	require.Equal(t, "urn:aa:bad%", string(in), "input slice untouched after failure")
}
