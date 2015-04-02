// Package ipcrypt implements IP-format-preserving encryption
/*
https://github.com/veorq/ipcrypt
*/
package ipcrypt

const (
	B0 uint32 = 0xff
	B1 uint32 = B0 << 8
	B2 uint32 = B1 << 8
	B3 uint32 = B2 << 8

	B0B2 uint32 = B0 | B2
	B1B3 uint32 = B1 | B3
)

type Key [4]uint32

// Setup a key.  Will truncate or zero-pad to 16 bytes.
func KeySetup(key []byte) Key {
	var k Key
	var tmp [4][4]byte

	for i := 0; i < 16 && i < len(key); i++ {
		tmp[i/4][i%4] = key[i]
	}
	for i := 0; i < 4; i++ {
		k[i] = toState(tmp[i])
	}

	return k
}

func toState(ip [4]byte) uint32 {
	return (uint32(ip[3]) << 24) | (uint32(ip[2]) << 16) | (uint32(ip[1]) << 8) | uint32(ip[0])
}

func fromState(s uint32) [4]byte {
	return [4]byte{byte(s), byte(s >> 8), byte(s >> 16), byte(s >> 24)}
}

// Encrypt a 4-byte value
func Encrypt(key Key, ip [4]byte) [4]byte {
	s := toState(ip)

	s ^= key[0]
	s = fwd(s)
	s ^= key[1]
	s = fwd(s)
	s ^= key[2]
	s = fwd(s)
	s ^= key[3]

	return fromState(s)
}

// Decrypt a 4-byte value with a 16-byte key
func Decrypt(key Key, ip [4]byte) [4]byte {
	s := toState(ip)

	s ^= key[3]
	s = bwd(s)
	s ^= key[2]
	s = bwd(s)
	s ^= key[1]
	s = bwd(s)
	s ^= key[0]

	return fromState(s)
}

func fwd(s uint32) uint32 {
	// b0 += b1
	// b2 += b3
	// b1 = rotl(b1, 2)
	// b3 = rotl(b3, 5)
	// b1 ^= b0
	// b3 ^= b2
	// b0 = rotl(b0, 4)
	// b0 += b3
	// b2 += b1
	// b1 = rotl(b1, 3)
	// b3 = rotl(b3, 7)
	// b1 ^= b2
	// b3 ^= b0
	// b2 = rotl(b2, 4)
	s = add(s, s>>8)
	s = rotlb1b3(s, 2, 5)
	s = xor(s, s<<8)
	s = rotl(s, 4, B0)
	s = add(s, (s<<8)|(s>>24))
	s = rotlb1b3(s, 3, 7)
	s = xor(s, (s<<24)|(s>>8))
	s = rotl(s, 4, B2)

	return s
}

func bwd(s uint32) uint32 {
	// b2 = rotl(b2, 4)
	// b1 ^= b2
	// b3 ^= b0
	// b1 = rotl(b1, 5)
	// b3 = rotl(b3, 1)
	// b2 -= b1
	// b0 -= b3
	// b0 = rotl(b0, 4)
	// b1 ^= b0
	// b3 ^= b2
	// b1 = rotl(b1, 6)
	// b3 = rotl(b3, 3)
	// b0 -= b1
	// b2 -= b3

	s = rotl(s, 4, B2)
	s = xor(s, (s<<24)|(s>>8))
	s = rotlb1b3(s, 5, 1)
	s = sub(s, (s<<8)|(s>>24))
	s = rotl(s, 4, B0)
	s = xor(s, s<<8)
	s = rotlb1b3(s, 6, 3)
	s = sub(s, s>>8)

	return s
}

func rotlb1b3(b uint32, ra, rb uint) uint32 {
	var unused uint32 = b & B0B2
	var a uint32 = b & B1
	b = b & B3

	a = (a << ra) | (a >> (8 - ra))
	a &= B1

	b = (b << rb) | (b >> (8 - rb))
	b &= B3

	return a | b | unused
}

func rotl(b uint32, r uint, mask uint32) uint32 {
	var unused uint32 = b & (^mask)

	b &= mask
	b = (b << r) | (b >> (8 - r))
	b &= mask

	return b | unused
}

func add(a, b uint32) uint32 {
	var unused uint32 = a & B1B3
	a &= B0B2
	b &= B0B2
	return ((a + b) & B0B2) | unused
}

func sub(a, b uint32) uint32 {
	var unused uint32 = a & B1B3
	a &= B0B2
	b &= B0B2
	return ((a - b) & B0B2) | unused
}

func xor(a, b uint32) uint32 {
	var unused uint32 = a & B0B2
	return ((a ^ b) & B1B3) | unused
}
