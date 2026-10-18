package action

import (
	"crypto/sha512"
	"fmt"
	"math/rand"
)
// SHA-512-based Unix crypt ($6$), per crypt(5) / the public-domain
// implementation by Ulrich Drepper. Used for user.set_password so the agent
// writes /etc/shadow entries glibc's crypt(3) accepts.

const crypt6Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

const (
	crypt6DefaultRounds = 5000
	crypt6MinRounds     = 1000
	crypt6MaxRounds     = 999999999
)

func crypt6B644(c1, c2, c3 byte) string {
	v := int(c1)<<16 | int(c2)<<8 | int(c3)
	s := make([]byte, 4)
	s[0] = crypt6Alphabet[v&0x3f]
	s[1] = crypt6Alphabet[(v>>6)&0x3f]
	s[2] = crypt6Alphabet[(v>>12)&0x3f]
	s[3] = crypt6Alphabet[(v>>18)&0x3f]
	return string(s)
}

func crypt6B642(c3 byte) string {
	s := make([]byte, 2)
	s[0] = crypt6Alphabet[c3&0x3f]
	s[1] = crypt6Alphabet[(c3>>6)&0x3f]
	return string(s)
}

// crypt6 hashes password against "$6$[rounds=N$]salt".
func crypt6(password, salt string, rounds int) (string, error) {
	if rounds == 0 {
		rounds = crypt6DefaultRounds
	}
	if rounds < crypt6MinRounds || rounds > crypt6MaxRounds {
		return "", fmt.Errorf("crypt6: rounds out of range")
	}
	saltBytes := []byte(salt)
	if len(saltBytes) > 16 {
		saltBytes = saltBytes[:16]
	}
	key := []byte(password)
	keyLen := len(key)
	saltLen := len(saltBytes)

	// digest = SHA512(key + salt + key); alt = same
	alt := sha512.Sum512(append(append(append([]byte{}, key...), saltBytes...), key...))

	// Add alt once per 64 key bytes, then the remainder.
	var cnt int
	ctx := sha512.New()
	ctx.Write(key)
	ctx.Write(saltBytes)
	for cnt = keyLen; cnt > 64; cnt -= 64 {
		ctx.Write(alt[:])
	}
	ctx.Write(alt[:cnt])

	// Binary length of the key: 1 bit -> alt, 0 bit -> key.
	for cnt = keyLen; cnt > 0; cnt >>= 1 {
		if cnt&1 != 0 {
			ctx.Write(alt[:])
		} else {
			ctx.Write(key)
		}
	}
	alt = *(*[64]byte)(ctx.Sum(nil))

	// P byte sequence: SHA512 repeated over key, one key per character.
	pctx := sha512.New()
	for cnt = 0; cnt < keyLen; cnt++ {
		pctx.Write(key)
	}
	temp := pctx.Sum(nil)
	pBytes := make([]byte, 0, keyLen)
	for cnt = keyLen; cnt >= 64; cnt -= 64 {
		pBytes = append(pBytes, temp[:64]...)
	}
	pBytes = append(pBytes, temp[:cnt]...)

	// S byte sequence: salt repeated 16 + alt_result[0] times.
	sctx := sha512.New()
	for cnt = 0; cnt < 16+int(alt[0]); cnt++ {
		sctx.Write(saltBytes)
	}
	temp = sctx.Sum(nil)
	sBytes := make([]byte, 0, saltLen)
	for cnt = saltLen; cnt >= 64; cnt -= 64 {
		sBytes = append(sBytes, temp[:64]...)
	}
	sBytes = append(sBytes, temp[:cnt]...)
	// The round loop.
	var result [64]byte
	copy(result[:], alt[:])
	for cnt := 0; cnt < rounds; cnt++ {
		ctx = sha512.New()
		if cnt&1 != 0 {
			ctx.Write(pBytes)
		} else {
			ctx.Write(result[:])
		}
		if cnt%3 != 0 {
			ctx.Write(sBytes)
		}
		if cnt%7 != 0 {
			ctx.Write(pBytes)
		}
		if cnt&1 != 0 {
			ctx.Write(result[:])
		} else {
			ctx.Write(pBytes)
		}
		result = *(*[64]byte)(ctx.Sum(nil))
	}

	// Encode.
	out := "$6$"
	if rounds != crypt6DefaultRounds {
		out += fmt.Sprintf("rounds=%d$", rounds)
	}
	out += string(saltBytes) + "$"
	// The 22 groups follow the Drepper byte ordering.
	groups := [][3]byte{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45},
		{25, 46, 4}, {47, 5, 26}, {6, 27, 48}, {28, 49, 7},
		{50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
		{12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57},
		{37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
		{62, 20, 41},
	}
	for _, g := range groups {
		out += crypt6B644(result[g[0]], result[g[1]], result[g[2]])
	}
	out += crypt6B642(result[63])
	return out, nil
}

// crypt6Salt generates a fresh 16-character salt from the crypt alphabet.
func crypt6Salt() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = crypt6Alphabet[rand.Intn(64)]
	}
	return string(b)
}

// verifyCrypt6 reports whether password hashes to the stored $6$ string.
func verifyCrypt6(password, stored string) bool {
	if len(stored) < 3 || stored[:3] != "$6$" {
		return false
	}
	rest := stored[3:]
	rounds := crypt6DefaultRounds
	saltPart := rest
	if len(rest) > 7 && rest[:7] == "rounds=" {
		end := 7
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		n := 0
		for _, c := range rest[7:end] {
			n = n*10 + int(c-'0')
		}
		if end < len(rest) && rest[end] == '$' {
			rounds = n
			saltPart = rest[end+1:]
		}
	}
	saltEnd := len(saltPart)
	for i, c := range saltPart {
		if c == '$' {
			saltEnd = i
			break
		}
	}
	if saltEnd <= 0 {
		return false
	}
	got, err := crypt6(password, saltPart[:saltEnd], rounds)
	if err != nil {
		return false
	}
	return got == stored
}
