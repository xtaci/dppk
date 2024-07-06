package dppk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDPPK(t *testing.T) {
	dppk, err := GenerateKey(5)
	assert.Nil(t, err)
	t.Log(dppk)

	Ps, Qs, err := dppk.Encrypt(dppk.PublicKey, []byte("hello world"))
	assert.Nil(t, err)
	t.Log("Ps:", Ps)
	t.Log("Qs:", Qs)
}
