package dppk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDPPK(t *testing.T) {
	dppk, err := GenerateKey(5)
	assert.Nil(t, err)
	t.Log(dppk)

	Ps, Qs, err := dppk.Encrypt(dppk.PublicKey, []byte("W"))
	assert.Nil(t, err)
	t.Log("Ps:", Ps)
	t.Log("Qs:", Qs)

	dec, err := dppk.Decrypt(Ps, Qs)
	t.Log(string(dec))
}
