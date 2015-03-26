// Package ipcrypt implements IP-format-preserving encryption
/*
https://github.com/veorq/ipcrypt
*/
package ipcrypt

type Key [4][4]byte

// Setup a key.  Will truncate or zero-pad to 16 bytes.
func KeySetup(key []byte) Key {
	var k Key

	for i := 0; i < 16 && i < len(key); i++ {
		k[i/4][i%4] = key[i]
	}

	return k
}

// Encrypt a 4-byte value
func Encrypt(key Key, ip [4]byte) [4]byte {
	s := state(ip)
	s = xor4(s, key[0])
	s = fwd(s)
	s = xor4(s, key[1])
	s = fwd(s)
	s = xor4(s, key[2])
	s = fwd(s)
	s = xor4(s, key[3])
	return s
}

// Decrypt a 4-byte value with a 16-byte key
func Decrypt(key Key, ip [4]byte) [4]byte {
	s := state(ip)
	s = xor4(s, key[3])
	s = bwd(s)
	s = xor4(s, key[2])
	s = bwd(s)
	s = xor4(s, key[1])
	s = bwd(s)
	s = xor4(s, key[0])
	return s
}

type state [4]byte

func fwd(s state) state {
	b0, b1, b2, b3 := s[0], s[1], s[2], s[3]
	b0 += b1
	b2 += b3
	b0 &= 0xff
	b2 &= 0xff
	b1 = rotl(b1, 2)
	b3 = rotl(b3, 5)
	b1 ^= b0
	b3 ^= b2
	b0 = rotl(b0, 4)
	b0 += b3
	b2 += b1
	b0 &= 0xff
	b2 &= 0xff
	b1 = rotl(b1, 3)
	b3 = rotl(b3, 7)
	b1 ^= b2
	b3 ^= b0
	b2 = rotl(b2, 4)
	return state{b0, b1, b2, b3}
}

func bwd(s state) state {
	b0, b1, b2, b3 := s[0], s[1], s[2], s[3]
	b2 = rotl(b2, 4)
	b1 ^= b2
	b3 ^= b0
	b1 = rotl(b1, 5)
	b3 = rotl(b3, 1)
	b0 -= b3
	b2 -= b1
	b0 &= 0xff
	b2 &= 0xff
	b0 = rotl(b0, 4)
	b1 ^= b0
	b3 ^= b2
	b1 = rotl(b1, 6)
	b3 = rotl(b3, 3)
	b0 -= b1
	b2 -= b3
	b0 &= 0xff
	b2 &= 0xff
	return state{b0, b1, b2, b3}
}

func rotl(b byte, r uint) byte {
	return ((b << r) & 0xff) | (b >> (8 - r))
}

func xor4(x [4]byte, y [4]byte) [4]byte {
	return [4]byte{x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]}
}
