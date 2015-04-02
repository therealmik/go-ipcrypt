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
	s = add(s, s>>8)
	s = rotl(s, 2, B1)
	s = rotl(s, 5, B3)
	s = xor(s, s<<8)
	s = rotl(s, 4, B0)
	s = add(s, (s<<8)|(s>>24))
	s = rotl(s, 3, B1)
	s = rotl(s, 7, B3)
	s = xor(s, (s<<24)|(s>>8))
	s = rotl(s, 4, B2)

	return s
}

func bwd(s uint32) uint32 {
	s = rotl(s, 4, B2)
	s = xor(s, (s<<24)|(s>>8))
	s = rotl(s, 5, B1)
	s = rotl(s, 1, B3)
	s = sub(s, (s<<8)|(s>>24))
	s = rotl(s, 4, B0)
	s = xor(s, s<<8)
	s = rotl(s, 6, B1)
	s = rotl(s, 3, B3)
	s = sub(s, s>>8)

	return s
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

	var result1 uint32 = (a - b) & 0xff
	var result2 uint32 = (((a >> 16) - (b >> 16)) & 0xff) << 16
	return result1 | result2 | unused
}

func xor(a, b uint32) uint32 {
	return a ^ (b & B1B3)
}
