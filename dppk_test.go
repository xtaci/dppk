package dppk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDPPK(t *testing.T) {
	dppk, err := GenerateKey(5)
	assert.Nil(t, err)
	t.Log(dppk)

	secret := []byte("W")
	Ps, Qs, err := dppk.Encrypt(&dppk.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("Ps:", Ps)
	t.Log("Qs:", Qs)
	t.Log("secret:", secret)

	dec, err := dppk.Decrypt(Ps, Qs)
	t.Log(string(dec))
}
