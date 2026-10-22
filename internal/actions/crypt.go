package actions

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
)

// SHA-512 crypt ($6$), Drepper's specification. Pure Go so no libcrypt is needed.

const (
	cryptDefaultRounds = 5000
	cryptMinRounds     = 1000
	cryptMaxRounds     = 999_999_999
	cryptVerifyMax     = 20_000_000 // refuse absurd round counts when verifying
	b64chars           = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// HashPassword returns a $6$ crypt hash with a random 16-char salt.
func HashPassword(password string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	for i, b := range raw {
		salt[i] = b64chars[int(b)&63]
	}
	return sha512Crypt([]byte(password), salt, cryptDefaultRounds, false), nil
}

// CheckPassword reports whether hash (a $6$ hash) matches password.
func CheckPassword(hash, password string) (bool, error) {
	if !strings.HasPrefix(hash, "$6$") {
		return false, errors.New("unsupported hash scheme (only $6$)")
	}
	rest := hash[3:]
	rounds, custom := cryptDefaultRounds, false
	if strings.HasPrefix(rest, "rounds=") {
		end := strings.IndexByte(rest, '$')
		if end < 0 {
			return false, errors.New("malformed hash")
		}
		n, err := strconv.Atoi(rest[7:end])
		if err != nil || n < 0 || n > cryptVerifyMax {
			return false, errors.New("bad rounds")
		}
		rounds, custom = max(cryptMinRounds, n), true
		rest = rest[end+1:]
	}
	end := strings.IndexByte(rest, '$')
	if end < 0 {
		return false, errors.New("malformed hash")
	}
	salt := rest[:end]
	if len(salt) > 16 {
		salt = salt[:16]
	}
	got := sha512Crypt([]byte(password), []byte(salt), rounds, custom)
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1, nil
}

func sha512Crypt(pw, salt []byte, rounds int, custom bool) string {
	if len(salt) > 16 {
		salt = salt[:16]
	}
	rounds = min(max(rounds, cryptMinRounds), cryptMaxRounds)

	b := sha512.New()
	b.Write(pw)
	b.Write(salt)
	b.Write(pw)
	B := b.Sum(nil)

	a := sha512.New()
	a.Write(pw)
	a.Write(salt)
	for n := len(pw); n > 0; n -= 64 {
		a.Write(B[:min(n, 64)])
	}
	for n := len(pw); n > 0; n >>= 1 {
		if n&1 != 0 {
			a.Write(B)
		} else {
			a.Write(pw)
		}
	}
	A := a.Sum(nil)

	dp := sha512.New()
	for i := 0; i < len(pw); i++ {
		dp.Write(pw)
	}
	P := repeatTo(dp.Sum(nil), len(pw))

	ds := sha512.New()
	for i := 0; i < 16+int(A[0]); i++ {
		ds.Write(salt)
	}
	S := repeatTo(ds.Sum(nil), len(salt))

	for i := 0; i < rounds; i++ {
		c := sha512.New()
		if i&1 != 0 {
			c.Write(P)
		} else {
			c.Write(A)
		}
		if i%3 != 0 {
			c.Write(S)
		}
		if i%7 != 0 {
			c.Write(P)
		}
		if i&1 != 0 {
			c.Write(A)
		} else {
			c.Write(P)
		}
		A = c.Sum(nil)
	}

	perm := [21][3]int{{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
		{28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
		{15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}}
	var out strings.Builder
	out.WriteString("$6$")
	if custom {
		out.WriteString("rounds=" + strconv.Itoa(rounds) + "$")
	}
	out.Write(salt)
	out.WriteByte('$')
	to64 := func(v uint32, n int) {
		for ; n > 0; n-- {
			out.WriteByte(b64chars[v&63])
			v >>= 6
		}
	}
	for _, t := range perm {
		to64(uint32(A[t[0]])<<16|uint32(A[t[1]])<<8|uint32(A[t[2]]), 4)
	}
	to64(uint32(A[63]), 2)
	return out.String()
}

func repeatTo(d []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, d[:min(len(d), n-len(out))]...)
	}
	return out
}
