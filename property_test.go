package urn

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const propertySeed = int64(0x5b1c0de)

type generatedURN struct {
	mode   ParsingMode
	raw    string
	prefix string
	id     string
	ss     string
	r      string
	q      string
	f      string
	scim   semanticSCIM
}

type semanticSCIM struct {
	typeName string
	name     string
	other    string
}

var (
	unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
	alnumChars      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nss2141Chars    = unreservedChars + "()+,.=@;$_!*':"
	nss8141Chars    = alnumChars + "~&()+,.=@;$_!*':/-"
	scimOtherChars  = unreservedChars + "()+,-.:=@;$_!*'"
	hexDigits       = "0123456789ABCDEFabcdef"
)

func TestBoundedGeneratedURNProperties(t *testing.T) {
	specs := []generatedURN{
		legalSpec(RFC2141Only, "URN:a:A%2Fz"),
		legalSpec(RFC2141Only, "urn:abcdefghilmnopqrstuvzabcdefghilm:()+,-.:=@;$_!*'x%FF"),
		legalSpec(RFC8141Only, "URN:ab:x%2f"),
		legalSpec(RFC8141Only, "urn:z------------------------------a:start~&/x?+R%AF~&/x?=Q%Be~&/x#F%Cd~&/x"),
		legalSpec(RFC8141Only, "urn:urn-7:CamelCase%2f?+r?=q#f"),
		legalSpec(RFC7643Only, "urn:ietf:params:scim:schemas:core:2.0:User"),
		legalSpec(RFC7643Only, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:userName"),
		legalSpec(RFC7643Only, "URN:ietf:params:scim:api:messages:2.0:ListResponse%2fX"),
		legalSpec(RFC7643Only, "urn:ietf:params:scim:param:Name1:Other%2F(a)+,-.:=@;$_!*'x"),
		legalSpec(RFC7643Only, "urn:ietf:params:scim:schemas:core"),
	}

	rng := rand.New(rand.NewSource(propertySeed))
	for mode := RFC2141Only; mode <= RFC8141Only; mode++ {
		for range 50 {
			specs = append(specs, generateLegalURN(rng, mode))
		}
	}

	for _, spec := range specs {
		t.Run(modeName(spec.mode)+"/"+spec.raw, func(t *testing.T) {
			if failure := generatedURNFailure(spec); failure != "" {
				shortest := shortestLegalFailure(spec.mode, spec.raw, generatedURNFailure)
				if shortest == "" {
					shortest = spec.raw
				}
				t.Fatalf("shortest %q: %s", shortest, failure)
			}
		})
	}
}

func FuzzGeneratedURN(f *testing.F) {
	for _, seed := range []int64{1, 2, 3, 7, 11, 13, 17, 19, 23, 101, 103, 107, 109, 113, 127} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, seed int64) {
		if seed == 0 {
			seed = propertySeed
		}
		mode := ParsingMode(1 + (int64(int(seed%3))+3)%3)
		spec := generateLegalURN(rand.New(rand.NewSource(seed)), mode)
		if failure := generatedURNFailure(spec); failure != "" {
			shortest := shortestLegalFailure(spec.mode, spec.raw, generatedURNFailure)
			if shortest == "" {
				shortest = spec.raw
			}
			t.Fatalf("seed=%d shortest=%q: %s", seed, shortest, failure)
		}
	})
}

func TestGeneratedRejections(t *testing.T) {
	t.Run("illegal percent encoding", func(t *testing.T) {
		for _, mode := range []ParsingMode{RFC2141Only, RFC8141Only} {
			for _, input := range []string{
				"urn:ab:x%",
				"urn:ab:x%2",
				"urn:ab:x%GG",
				"urn:ab:x%0G",
				"urn:ab:x%g0",
			} {
				assertRejected(t, mode, input)
			}
		}
		assertRejected(t, RFC8141Only, "urn:ab:x?+r%0G")
		assertRejected(t, RFC8141Only, "urn:ab:x?=q%GG")
		assertRejected(t, RFC8141Only, "urn:ab:x#f%0g")
		for _, input := range []string{
			"urn:ietf:params:scim:api:messages:x%",
			"urn:ietf:params:scim:api:messages:x%2",
			"urn:ietf:params:scim:schemas:core:2.0:User%GG",
			"urn:ietf:params:scim:schemas:core:2.0:User%0G",
		} {
			assertRejected(t, RFC7643Only, input)
		}
	})

	t.Run("empty required components", func(t *testing.T) {
		for _, input := range []string{"", "urn", "urn:", "urn::", "urn:ab:"} {
			assertRejected(t, RFC2141Only, input)
			assertRejected(t, RFC8141Only, input)
		}
		for _, input := range []string{
			"",
			"urn",
			"urn:",
			"urn::",
			"urn:a:",
			"urn:ietf:params:scim:schemas:core:",
			"urn:ietf:params:scim:schemas:",
			"urn:ietf:params:scim:",
		} {
			assertRejected(t, RFC7643Only, input)
		}
		assertRejected(t, RFC8141Only, "urn:ab:x?+")
		assertRejected(t, RFC8141Only, "urn:ab:x?=")
	})
}

func TestNormalizeIdempotent(t *testing.T) {
	tests := []struct {
		mode  ParsingMode
		input string
	}{
		{RFC2141Only, "urn:ab:x%2f"},
		{RFC8141Only, "urn:ab:x?=q#f"},
		{RFC7643Only, "urn:ietf:params:scim:schemas:core:2.0:User"},
	}
	for _, tt := range tests {
		t.Run(modeName(tt.mode), func(t *testing.T) {
			u := mustParse(t, tt.mode, tt.input)
			once := u.Normalize().String()
			twice := u.Normalize().Normalize().String()
			assert.Equal(t, once, twice)
		})
	}
}

func TestRFC8141StringFidelityPreservesInformalPrefixCase(t *testing.T) {
	u := mustParse(t, RFC8141Only, "URN:urn-7:CamelCase")
	assert.Equal(t, "URN:urn-7:CamelCase", u.String())
}

func TestModeBoundariesAreExclusive(t *testing.T) {
	assertRejected(t, RFC2141Only, "urn:ab:nss?+r")
	assertRejected(t, RFC2141Only, "urn:ab:nss?=q")
	assertRejected(t, RFC2141Only, "urn:ab:nss#f")
	assertRejected(t, RFC2141Only, "urn:ab:nss~")
	assertRejected(t, RFC2141Only, "urn:ab:nss&")
	assertRejected(t, RFC2141Only, "urn:ab:nss/")
	assertRejected(t, RFC8141Only, "urn:a:nss")
	assertRejected(t, RFC8141Only, "urn:"+strings.Repeat("a", 33)+":nss")
	assertRejected(t, RFC8141Only, "urn:ab:/nss")
	assertRejected(t, RFC8141Only, "urn:ab:x?+r?+s")
	assertRejected(t, RFC8141Only, "urn:ab:x?=q?=s")

	for _, input := range []string{
		"urn:ab:nss",
		"URN:IETF:params:scim:schemas:core",
		"urn:ietf:params:scim:schemas:core:2.0:User?+r",
		"urn:ietf:params:scim:schemas:core:2.0:User#f",
	} {
		assertRejected(t, RFC7643Only, input)
	}

	scimInput := "urn:ietf:params:scim:schemas:core"
	scimURN := mustParse(t, RFC7643Only, scimInput)
	for _, mode := range []ParsingMode{RFC2141Only, RFC8141Only} {
		ordinary := mustParse(t, mode, scimInput)
		require.False(t, ordinary.IsSCIM())
		require.Nil(t, ordinary.SCIM())
		assert.False(t, scimURN.Equal(ordinary))
		assert.False(t, ordinary.Equal(scimURN))
	}
}

func TestFailedParseDoesNotReusePreviousFields(t *testing.T) {
	tests := []struct {
		mode    ParsingMode
		valid   string
		invalid string
	}{
		{RFC2141Only, "urn:ab:valid%FF", "urn:ab:valid%FF?+r"},
		{RFC8141Only, "urn:ab:valid%FF?+r?=q#f", "urn:ab:valid%FF?+r?=q?="},
		{RFC7643Only, "urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:core:2.0:User?+r"},
	}
	for _, tt := range tests {
		t.Run(modeName(tt.mode), func(t *testing.T) {
			m := NewMachine(WithParsingMode(tt.mode))
			first, err := m.Parse([]byte(tt.valid))
			require.NoError(t, err)
			require.NotNil(t, first)

			failed, err := m.Parse([]byte(tt.invalid))
			require.Error(t, err)
			assert.Nil(t, failed)
			assert.Same(t, err, m.Error())

			second, err := m.Parse([]byte(tt.valid))
			require.NoError(t, err)
			require.NotNil(t, second)
			assert.Empty(t, generatedURNFailure(describeParsed(tt.mode, second)))
		})
	}
}

func TestMutationOraclesCanFail(t *testing.T) {
	t.Run("lowercase percent encoding changes fidelity but not equivalence", func(t *testing.T) {
		original := "urn:ab:Ab%2fX%af"
		mutated := upperPercentHex(original)
		u := mustParse(t, RFC2141Only, original)
		v := mustParse(t, RFC2141Only, mutated)
		require.NotEqual(t, original, mutated)
		assert.Equal(t, original, u.String())
		assert.Equal(t, mutated, v.String())
		assert.NotEqual(t, u.String(), v.String())
		assert.True(t, u.Equal(v))
		assert.True(t, v.Equal(u))
	})

	t.Run("ignoring q component loses string fidelity but not equivalence", func(t *testing.T) {
		input := "urn:ab:nss?+r?=q%2f#f"
		u := mustParse(t, RFC8141Only, input)
		withoutQ := removeQComponent(input)
		v := mustParse(t, RFC8141Only, withoutQ)
		require.NotEmpty(t, u.QComponent())
		require.NotEqual(t, input, withoutQ)
		assert.Equal(t, input, u.String())
		assert.True(t, u.Equal(v))
		assert.True(t, v.Equal(u))
	})

	t.Run("reusing ordinary nid rules invalidates SCIM comparison", func(t *testing.T) {
		scimURN := mustParse(t, RFC7643Only, "urn:ietf:params:scim:schemas:core")
		ordinary := mustParse(t, RFC2141Only, "URN:IETF:params:scim:schemas:core")
		require.False(t, scimURN.Equal(ordinary))
		require.False(t, ordinary.Equal(scimURN))
		assert.Equal(t, ordinaryKey(scimURN), ordinaryKey(ordinary))
	})
}

func TestShortestLegalFailureShrinks(t *testing.T) {
	input := "urn:ab:xxxxx"
	shortest := shortestLegalFailure(RFC2141Only, input, func(spec generatedURN) string {
		if strings.Contains(spec.ss, "x") {
			return "synthetic failure"
		}
		return ""
	})
	assert.Equal(t, "urn:b:x", shortest)
}

func modeName(mode ParsingMode) string {
	switch mode {
	case RFC2141Only:
		return "rfc2141"
	case RFC7643Only:
		return "rfc7643"
	case RFC8141Only:
		return "rfc8141"
	default:
		return fmt.Sprintf("mode-%d", mode)
	}
}

func legalSpec(mode ParsingMode, input string) generatedURN {
	u, err := NewMachine(WithParsingMode(mode)).Parse([]byte(input))
	if err != nil {
		panic(err)
	}
	spec := describeParsed(mode, u)
	spec.raw = input
	return spec
}

func describeParsed(mode ParsingMode, u *URN) generatedURN {
	spec := generatedURN{
		mode:   mode,
		raw:    u.String(),
		prefix: u.prefix,
		id:     u.ID,
		ss:     u.SS,
		r:      u.rComponent,
		q:      u.qComponent,
		f:      u.fComponent,
	}
	if s := u.SCIM(); s != nil {
		spec.scim = semanticSCIM{
			typeName: s.Type.String(),
			name:     s.Name,
			other:    s.Other,
		}
	}
	return spec
}

func mustParse(t *testing.T, mode ParsingMode, input string) *URN {
	t.Helper()
	u, err := NewMachine(WithParsingMode(mode)).Parse([]byte(input))
	require.NoError(t, err)
	require.NotNil(t, u)
	return u
}

func assertRejected(t *testing.T, mode ParsingMode, input string) {
	t.Helper()
	u, err := NewMachine(WithParsingMode(mode)).Parse([]byte(input))
	assert.Nil(t, u)
	assert.Error(t, err)
}

func generateLegalURN(rng *rand.Rand, mode ParsingMode) generatedURN {
	if mode == RFC7643Only {
		return generateLegalSCIM(rng)
	}

	id := randomLegalNID(rng, mode)
	prefix := randomCase(rng, "urn")
	if mode == RFC8141Only && strings.HasPrefix(strings.ToLower(id), "urn-") {
		prefix = "urn"
	}
	nss := randomLegalComponent(rng, mode == RFC8141Only)
	raw := prefix + ":" + id + ":" + nss
	spec := generatedURN{
		mode:   mode,
		raw:    raw,
		prefix: prefix,
		id:     id,
		ss:     nss,
	}
	if mode == RFC8141Only {
		if rng.Intn(4) == 0 {
			spec.r = randomLegalComponent(rng, true)
			raw += "?+" + spec.r
		}
		if rng.Intn(3) == 0 {
			spec.q = randomLegalComponent(rng, true)
			raw += "?=" + spec.q
		}
		if rng.Intn(4) == 0 {
			spec.f = randomLegalComponent(rng, true)
			raw += "#" + spec.f
		}
		spec.raw = raw
	}
	return spec
}

func generateLegalSCIM(rng *rand.Rand) generatedURN {
	prefix := randomCase(rng, "urn")
	typeNames := []string{"schemas", "api", "param"}
	typeName := typeNames[rng.Intn(len(typeNames))]
	name := randomSCIMName(rng)
	ss := typeName + ":" + name
	raw := prefix + ":ietf:params:scim:" + ss

	other := ""
	if typeName == "schemas" && rng.Intn(2) == 0 {
		schemaFragments := []string{
			"core:2.0:User",
			"extension:enterprise:2.0:User:userName",
			"core:2.0:Group",
		}
		other = schemaFragments[rng.Intn(len(schemaFragments))]
	} else if rng.Intn(2) == 0 {
		other = randomLegalSCIMOther(rng)
	}
	if other != "" {
		ss += ":" + other
		raw += ":" + other
	}

	return generatedURN{
		mode:   RFC7643Only,
		raw:    raw,
		prefix: prefix,
		id:     "ietf:params:scim",
		ss:     ss,
		scim: semanticSCIM{
			typeName: typeName,
			name:     name,
			other:    other,
		},
	}
}

func randomCase(rng *rand.Rand, input string) string {
	result := make([]byte, len(input))
	for i := range input {
		result[i] = input[i]
		if rng.Intn(2) == 0 {
			result[i] -= 32
		}
	}
	return string(result)
}

func randomLegalNID(rng *rand.Rand, mode ParsingMode) string {
	if mode == RFC2141Only {
		if rng.Intn(5) == 0 {
			id := randomString(rng, alnumChars, 1, 32)
			for startsWithRejected2141NID(id) {
				id = randomString(rng, alnumChars, 1, 32)
			}
			return id
		}
	} else if rng.Intn(5) == 0 {
		if rng.Intn(2) == 0 {
			return "urn-" + randomString(rng, "123456789", 1, 1) + randomString(rng, alnumChars, 0, 27)
		}
		return randomString(rng, alnumChars, 2, 32)
	}
	id := randomString(rng, alnumChars, 2, 16)
	if mode == RFC2141Only {
		for startsWithRejected2141NID(id) {
			id = randomString(rng, alnumChars, 2, 16)
		}
	}
	return id
}

func startsWithRejected2141NID(id string) bool {
	return len(id) > 1 && strings.HasPrefix(strings.ToLower(id), "u")
}

func randomLegalComponent(rng *rand.Rand, allow8141 bool) string {
	charset := nss2141Chars
	if allow8141 {
		charset = nss8141Chars
	}
	length := rng.Intn(12) + 1
	var result []byte
	for i := 0; i < length; i++ {
		if allow8141 && len(result) > 0 && result[len(result)-1] == '/' {
			result = append(result, randomByte(rng, unreservedChars))
			continue
		}
		if rng.Intn(5) == 0 {
			result = append(result, '%', randomByte(rng, hexDigits), randomByte(rng, hexDigits))
		} else {
			result = append(result, randomByte(rng, charset))
		}
	}
	if allow8141 && result[0] == '/' {
		result[0] = randomByte(rng, unreservedChars)
	}
	return string(result)
}

func randomSCIMName(rng *rand.Rand) string {
	return randomString(rng, alnumChars, 1, 8)
}

func randomLegalSCIMOther(rng *rand.Rand) string {
	length := rng.Intn(10) + 1
	var result []byte
	for range length {
		if rng.Intn(5) == 0 {
			result = append(result, '%', randomByte(rng, hexDigits), randomByte(rng, hexDigits))
		} else {
			result = append(result, randomByte(rng, scimOtherChars))
		}
	}
	return string(result)
}

func randomString(rng *rand.Rand, charset string, min, max int) string {
	length := min
	if max > min {
		length += rng.Intn(max - min + 1)
	}
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rng.Intn(len(charset))]
	}
	return string(result)
}

func randomByte(rng *rand.Rand, charset string) byte {
	return charset[rng.Intn(len(charset))]
}

func sameSemanticComponents(left, right *URN) bool {
	if left.prefix != right.prefix || left.ID != right.ID || left.SS != right.SS {
		return false
	}
	if left.rComponent != right.rComponent || left.qComponent != right.qComponent || left.fComponent != right.fComponent {
		return false
	}
	if left.kind != right.kind {
		return false
	}
	if (left.scim == nil) != (right.scim == nil) {
		return false
	}
	return left.scim == nil || *left.scim == *right.scim
}

func generatedURNFailure(spec generatedURN) string {
	u, err := NewMachine(WithParsingMode(spec.mode)).Parse([]byte(spec.raw))
	if err != nil {
		return "generated input rejected: " + err.Error()
	}
	if u.String() != spec.raw {
		return fmt.Sprintf("string fidelity: got %q want %q", u.String(), spec.raw)
	}
	reparsedFromFidelity, err := NewMachine(WithParsingMode(spec.mode)).Parse([]byte(u.String()))
	if err != nil {
		return "String output rejected on second parse: " + err.Error()
	}
	if !sameSemanticComponents(u, reparsedFromFidelity) {
		return "parse-string-parse did not preserve components"
	}
	if u.prefix != spec.prefix || u.ID != spec.id || u.SS != spec.ss {
		return fmt.Sprintf("components got prefix=%q id=%q ss=%q want prefix=%q id=%q ss=%q", u.prefix, u.ID, u.SS, spec.prefix, spec.id, spec.ss)
	}
	if u.rComponent != spec.r || u.qComponent != spec.q || u.fComponent != spec.f {
		return fmt.Sprintf("8141 components got r=%q q=%q f=%q want r=%q q=%q f=%q", u.rComponent, u.qComponent, u.fComponent, spec.r, spec.q, spec.f)
	}

	canonical := canonicalURNString(u)
	if u.Normalize().String() != canonical {
		return fmt.Sprintf("normalized string got %q want %q", u.Normalize().String(), canonical)
	}
	reparsed, err := NewMachine(WithParsingMode(spec.mode)).Parse([]byte(canonical))
	if err != nil {
		return "normalized string is not parseable: " + err.Error()
	}
	if reparsed.Normalize().String() != canonical {
		return "normalization does not stabilize after reparsing"
	}

	if spec.mode == RFC7643Only {
		if !u.IsSCIM() || u.SCIM() == nil {
			return "SCIM kind lost"
		}
		if scim := u.SCIM(); scim.Type.String() != spec.scim.typeName || scim.Name != spec.scim.name || scim.Other != spec.scim.other {
			return fmt.Sprintf("SCIM components got type=%q name=%q other=%q want type=%q name=%q other=%q", scim.Type.String(), scim.Name, scim.Other, spec.scim.typeName, spec.scim.name, spec.scim.other)
		}
	} else if u.IsSCIM() || u.SCIM() != nil {
		return "non-SCIM mode produced a SCIM object"
	}

	if !u.Equal(u) {
		return "Equal is not reflexive"
	}

	variant := makeEquivalent(spec)
	v, err := NewMachine(WithParsingMode(spec.mode)).Parse([]byte(variant.raw))
	if err != nil {
		return "equivalent transformation rejected: " + err.Error()
	}
	if !u.Equal(v) || !v.Equal(u) {
		return fmt.Sprintf("Equal rejects equivalent transformation %q vs %q", u.String(), v.String())
	}

	if spec.mode == RFC8141Only {
		qVariant := spec
		qVariant.q = "different-q"
		qVariant.raw = appendComponent(qVariant)
		q, err := NewMachine(WithParsingMode(spec.mode)).Parse([]byte(qVariant.raw))
		if err != nil {
			return "q-component equivalent rejected: " + err.Error()
		}
		if !u.Equal(q) || !q.Equal(u) {
			return "Equal incorrectly compares q-component"
		}
	}

	return ""
}

func canonicalURNString(u *URN) string {
	canonical := "urn:" + strings.ToLower(u.ID) + ":" + lowercasePercentHex(u.SS)
	return canonical
}

func lowercasePercentHex(input string) string {
	result := make([]byte, len(input))
	copy(result, input)
	for i := 0; i+2 < len(result); i++ {
		if result[i] == '%' {
			result[i+1] = lowerHexByte(result[i+1])
			result[i+2] = lowerHexByte(result[i+2])
		}
	}
	return string(result)
}

func upperPercentHex(input string) string {
	result := make([]byte, len(input))
	copy(result, input)
	for i := 0; i+2 < len(result); i++ {
		if result[i] == '%' {
			result[i+1] = upperHexByte(result[i+1])
			result[i+2] = upperHexByte(result[i+2])
		}
	}
	return string(result)
}

func lowerHexByte(value byte) byte {
	if value >= 'A' && value <= 'F' {
		return value + 32
	}
	return value
}

func upperHexByte(value byte) byte {
	if value >= 'a' && value <= 'f' {
		return value - 32
	}
	return value
}

func makeEquivalent(spec generatedURN) generatedURN {
	variant := spec
	if spec.mode == RFC7643Only {
		variant.raw = lowercasePercentHex(spec.raw)
		return variant
	}
	variant.prefix = strings.ToLower(spec.prefix)
	variant.id = strings.ToLower(spec.id)
	variant.ss = lowercasePercentHex(spec.ss)
	variant.r = lowercasePercentHex(spec.r)
	variant.q = lowercasePercentHex(spec.q)
	variant.f = lowercasePercentHex(spec.f)
	variant.raw = appendComponent(variant)
	return variant
}

func appendComponent(variant generatedURN) string {
	result := variant.prefix + ":" + variant.id + ":" + variant.ss
	if variant.r != "" {
		result += "?+" + variant.r
	}
	if variant.q != "" {
		result += "?=" + variant.q
	}
	if variant.f != "" {
		result += "#" + variant.f
	}
	return result
}

func shortestLegalFailure(mode ParsingMode, initial string, fails func(generatedURN) string) string {
	shortest := initial
	changed := true
	for changed {
		changed = false
		for i := range shortest {
			candidate := shortest[:i] + shortest[i+1:]
			u, err := NewMachine(WithParsingMode(mode)).Parse([]byte(candidate))
			if err != nil {
				continue
			}
			if fails(describeParsed(mode, u)) != "" {
				shortest = candidate
				changed = true
				break
			}
		}
	}
	return shortest
}

func removeQComponent(input string) string {
	start := strings.Index(input, "?=")
	if start < 0 {
		return input
	}
	end := start + 2
	for end < len(input) && input[end] != '#' {
		end++
	}
	return input[:start] + input[end:]
}

func ordinaryKey(u *URN) string {
	return strings.ToLower(u.ID) + ":" + lowercasePercentHex(u.SS)
}
