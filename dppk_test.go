package dppk

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDPPK(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	secret := []byte("hello quantum")
	kem, err := Encrypt(&alice.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("secret:", string(secret))

	x1, x2, err := alice.Decrypt(kem)
	assert.Nil(t, err)
	t.Log("x1:", string(x1.Bytes()))
	t.Log("x2:", string(x2.Bytes()))

	assert.Equal(t, alice.Public().Order(), 10)

	equal := bytes.Equal(secret, x1.Bytes()) || bytes.Equal(secret, x2.Bytes())
	assert.True(t, equal)
}

func TestDPPKSmallPrime(t *testing.T) {
	prime := "977"
	alice, err := GenerateKeyWithPrime(10, prime)
	assert.Nil(t, err)

	secret := []byte("X")
	kem, err := Encrypt(&alice.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("secret:", string(secret))

	x1, x2, err := alice.Decrypt(kem)
	assert.Nil(t, err)
	t.Log("x1:", string(x1.Bytes()))
	t.Log("x2:", string(x2.Bytes()))

	equal := bytes.Equal(secret, x1.Bytes()) || bytes.Equal(secret, x2.Bytes())
	assert.True(t, equal)
}

func BenchmarkDPPKEncrypt(b *testing.B) {
	dppk, _ := GenerateKey(5)
	secret := []byte("hello quantum")
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(&dppk.PublicKey, secret)
	}
}

func BenchmarkDPPKDecrypt(b *testing.B) {
	dppk, _ := GenerateKey(5)
	secret := []byte("hello quantum")
	kem, _ := Encrypt(&dppk.PublicKey, secret)
	for i := 0; i < b.N; i++ {
		_, _, _ = dppk.Decrypt(kem)
	}
}
