package dppk

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDPPK(t *testing.T) {
	dppk, err := GenerateKey(5)
	assert.Nil(t, err)

	secret := []byte("hello quantum")
	Ps, Qs, err := dppk.Encrypt(&dppk.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("secret:", string(secret))

	x1, x2, err := dppk.Decrypt(Ps, Qs)
	t.Log("x1:", string(x1.Bytes()))
	t.Log("x2:", string(x2.Bytes()))

	equal := bytes.Equal(secret, x1.Bytes()) || bytes.Equal(secret, x2.Bytes())
	assert.True(t, equal)
}
