package dppk

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// PRIME is the prime number used in the DPPK protocol.
const PRIME = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637"

// PrivateKey
type PrivateKey struct {
	s0             *big.Int
	a0, a1, b0, b1 *big.Int
	PublicKey
}

type PublicKey struct {
	Prime   *big.Int
	VectorP []*big.Int
	VectorQ []*big.Int
}

// NewDPPK creates a new DPPK instance with the given order.
func GenerateKey(order int) (*PrivateKey, error) {
	if order < 5 {
		return nil, errors.New("order must be at least 5")
	}
	prime, _ := big.NewInt(0).SetString(PRIME, 10)

RETRY:
	a0, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	a1, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	b0, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	b1, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	// make sure they're different
	if a0.Cmp(a1) == 0 || a0.Cmp(b0) == 0 || a0.Cmp(b1) == 0 || a1.Cmp(b0) == 0 || a1.Cmp(b1) == 0 || b0.Cmp(b1) == 0 {
		goto RETRY
	}

	// Bn(X)
	// coefficients s
	coeff_base := make([]*big.Int, order+1)
	for i := 0; i < len(coeff_base); i++ {
		r, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		coeff_base[i] = r
	}

	// vecP and vecQ
	vecP := make([]*big.Int, order+3)
	vecQ := make([]*big.Int, order+3)
	for i := 0; i < order+3; i++ {
		vecP[i] = big.NewInt(0)
		vecQ[i] = big.NewInt(0)
	}

	bigInt := new(big.Int)

	for i := 0; i < order+1; i++ {
		vecP[i].Mul(a0, coeff_base[i])
		vecP[i+1].Add(vecP[i+1], bigInt.Mul(a1, coeff_base[i]))
		vecP[i+2].Add(vecP[i+2], coeff_base[i])

		vecQ[i].Mul(b0, coeff_base[i])
		vecQ[i+1].Add(vecQ[i+1], bigInt.Mul(b1, coeff_base[i]))
		vecQ[i+2].Add(vecQ[i+2], coeff_base[i])

		vecP[i].Mod(vecP[i], prime)
		vecP[i+1].Mod(vecP[i+1], prime)
		vecP[i+2].Mod(vecP[i+2], prime)

		vecQ[i].Mod(vecQ[i], prime)
		vecQ[i+1].Mod(vecQ[i+1], prime)
		vecQ[i+2].Mod(vecQ[i+2], prime)
	}

	//fmt.Println(vecP[0], bigInt.Mod(bigInt.Mul(a0, coeff_base[0]), prime))
	priv := &PrivateKey{
		s0: coeff_base[0],
		a0: a0,
		a1: a1,
		b0: b0,
		b1: b1,
	}
	priv.PublicKey.VectorP = vecP[1 : order+2]
	priv.PublicKey.VectorQ = vecQ[1 : order+2]
	priv.PublicKey.Prime = prime
	return priv, nil
}

func (dppk *PrivateKey) Encrypt(pk PublicKey, msg []byte) (Ps []byte, Qs []byte, err error) {
	data := new(big.Int).SetBytes(msg)
	if data.Cmp(dppk.PublicKey.Prime) >= 0 {
		return nil, nil, errors.New("data is too large")
	}

	ps := new(big.Int)
	bigInt := new(big.Int)
	for i := range pk.VectorP {
		bigInt.Exp(data, big.NewInt(int64(i)), pk.Prime)
		bigInt.Mul(bigInt, pk.VectorP[i])
		ps.Mod(bigInt.Add(ps, bigInt), pk.Prime)
	}

	qs := new(big.Int)
	for i := range pk.VectorQ {
		bigInt.Exp(data, big.NewInt(int64(i)), pk.Prime)
		bigInt.Mul(bigInt, pk.VectorQ[i])
		qs.Mod(bigInt.Add(qs, bigInt), pk.Prime)
	}

	return ps.Bytes(), qs.Bytes(), nil
}
