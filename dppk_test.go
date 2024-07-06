package dppk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDPK(t *testing.T) {
	dppk, err := NewDPPK(5)
	assert.Nil(t, err)
	t.Log(dppk)
}
