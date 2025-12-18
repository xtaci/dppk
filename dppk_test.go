// # Copyright (c) 2024 xtaci
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

	message, err := alice.DecryptMessage(kem)
	assert.Nil(t, err)
	assert.Equal(t, secret, message)

	x1, x2, err := alice.Decrypt(kem)
	assert.Nil(t, err)
	t.Log("x1:", string(x1.Bytes()))
	t.Log("x2:", string(x2.Bytes()))

	assert.Equal(t, alice.Public().Order(), 10)

	decoded1, err1 := RecoverMessage(x1)
	decoded2, err2 := RecoverMessage(x2)
	equal := (err1 == nil && bytes.Equal(secret, decoded1)) || (err2 == nil && bytes.Equal(secret, decoded2))
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

	message, err := alice.DecryptMessage(kem)
	assert.Nil(t, err)
	assert.Equal(t, secret, message)

	x1, x2, err := alice.Decrypt(kem)
	assert.Nil(t, err)
	t.Log("x1:", string(x1.Bytes()))
	t.Log("x2:", string(x2.Bytes()))

	decoded1, err1 := RecoverMessage(x1)
	decoded2, err2 := RecoverMessage(x2)
	equal := (err1 == nil && bytes.Equal(secret, decoded1)) || (err2 == nil && bytes.Equal(secret, decoded2))
	assert.True(t, equal)
}

func TestDPPKLeadingZeros(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	secret := []byte{0x00, 0x00, 0x42, 0x10}
	kem, err := Encrypt(&alice.PublicKey, secret)
	assert.Nil(t, err)

	message, err := alice.DecryptMessage(kem)
	assert.Nil(t, err)
	assert.Equal(t, secret, message)
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
