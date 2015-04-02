package ipcrypt

import (
	"testing"

	"github.com/dgryski/go-skip32"
	"math/rand"
)

func TestFwdBwd(t *testing.T) {
	for i := 0; i < 16; i++ {
		s := rand.Uint32()
		r := fwd(s)
		q := bwd(r)
		if q != s {
			t.Errorf("fwd(%08x) = %08x; bwd(%08x) = %08x (diff=%08x)", s, r, r, q, s ^ q)
		}
	}
}

func TestRoundtrip(t *testing.T) {

	key := Key{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}

	ip := [4]byte{1, 2, 3, 4}

	for i := 0; i < 100; i++ {
		ip = Encrypt(key, ip)
	}

	if ip != [4]byte{107, 47, 222, 186} {
		t.Errorf("Encrypt failed, result %v", ip)
	}

	for i := 0; i < 100; i++ {
		ip = Decrypt(key, ip)
	}

	if ip != [4]byte{1, 2, 3, 4} {
		t.Errorf("Decrypt failed, result %v", ip)
	}
}

func BenchmarkIPCrypt(b *testing.B) {

	key := Key{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}
	ip := [4]byte{1, 2, 3, 4}

	for i := 0; i < b.N; i++ {
		Encrypt(key, ip)
	}
}

func BenchmarkSkip32(b *testing.B) {

	key := [10]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ip := uint32(0x01020304)

	s, _ := skip32.New(key[:])

	for i := 0; i < b.N; i++ {
		s.Obfus(ip)
	}
}

func TestROTL(t *testing.T) {
	s := rotl(0x71ffffff, 4, B3)
	if s != 0x17ffffff {
		t.Errorf("rotl doesn't work: %x", s)
	}

	s = rotl(0xffff71ff, 4, B1)
	if s != 0xffff17ff {
		t.Errorf("rotl doesn't work: %x", s)
	}
}

func TestAdd(t *testing.T) {
	var a uint32 = 0xff01ff01
	var b uint32 = 0xffffffff
	s := add(a, b)
	if s != 0xff00ff00 {
		t.Errorf("add doesn't work: %x", s)
	}
}

func TestSub(t *testing.T) {
	var a uint32 = 0xff0000ff
	var b uint32 = 0x77011111
	s := sub(a, b)
	if s != 0xffff00ee {
		t.Errorf("sub doesn't work: %x", s)
	}
}

func TestXor(t *testing.T) {
	var a uint32 = 0x55111111
	var b uint32 = 0xcc772211
	s := xor(a, b)
	if s != 0x99113311 {
		t.Errorf("xor doesn't work: %x", s)
	}
}
