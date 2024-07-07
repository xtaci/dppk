package dppk

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// PRIME is the prime number used in the DPPK protocol.
//const PRIME = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637"

const PRIME = "997"

// PrivateKey
type PrivateKey struct {
	s0             *big.Int
	a0, a1, b0, b1 *big.Int
	s0a0, s0b0     *big.Int
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
	// coefficients s^0 --> s^N
	Bn := make([]*big.Int, order)
	for i := 0; i < len(Bn); i++ {
		r, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		Bn[i] = r
	}
	// the coefficient of x^n is 1
	Bn = append(Bn, big.NewInt(1))

	// vecP and vecQ
	vecP := make([]*big.Int, order+3)
	vecQ := make([]*big.Int, order+3)
	for i := 0; i < order+3; i++ {
		vecP[i] = big.NewInt(0)
		vecQ[i] = big.NewInt(0)
	}

	bigInt := new(big.Int)

	//  x^2 + a1x + a0
	for i := 0; i < order+1; i++ {
		// vector P
		vecP[i].Add(vecP[i], bigInt.Mul(a0, Bn[i]))
		vecP[i].Mod(vecP[i], prime)

		vecP[i+1].Add(vecP[i+1], bigInt.Mul(a1, Bn[i]))
		vecP[i+1].Mod(vecP[i+1], prime)

		vecP[i+2].Add(vecP[i+2], Bn[i])
		vecP[i+2].Mod(vecP[i+2], prime)

		// vector Q
		vecQ[i].Add(vecQ[i], bigInt.Mul(b0, Bn[i]))
		vecQ[i].Mod(vecQ[i], prime)

		vecQ[i+1].Add(vecQ[i+1], bigInt.Mul(b1, Bn[i]))
		vecQ[i+1].Mod(vecQ[i+1], prime)

		vecQ[i+2].Add(vecQ[i+2], Bn[i])
		vecQ[i+2].Mod(vecQ[i+2], prime)
	}

	//fmt.Println(vecP[0], bigInt.Mod(bigInt.Mul(a0, coeff_base[0]), prime))
	priv := &PrivateKey{
		s0:   Bn[0],
		a0:   a0,
		a1:   a1,
		b0:   b0,
		b1:   b1,
		s0a0: vecP[0],
		s0b0: vecQ[0],
	}

	// remove v0 and v(N+2)
	priv.PublicKey.VectorP = vecP[1 : order+2]
	priv.PublicKey.VectorQ = vecQ[1 : order+2]
	priv.PublicKey.Prime = prime
	return priv, nil
}

func (dppk *PrivateKey) Encrypt(pk *PublicKey, msg []byte) (Ps *big.Int, Qs *big.Int, err error) {
	secret := new(big.Int).SetBytes(msg)
	if secret.Cmp(dppk.PublicKey.Prime) >= 0 {
		return nil, nil, errors.New("data is too large")
	}
	vecP := make([]*big.Int, len(dppk.PublicKey.VectorP)+1)
	vecQ := make([]*big.Int, len(dppk.PublicKey.VectorQ)+1)
	copy(vecP, pk.VectorP)
	copy(vecQ, pk.VectorQ)
	vecP[len(vecP)-1] = big.NewInt(1)
	vecQ[len(vecQ)-1] = big.NewInt(1)

	Ps = big.NewInt(0)
	Qs = big.NewInt(0)
	Si := new(big.Int).Set(secret)
	UiSi := new(big.Int)
	ViSi := new(big.Int)

	for i := range vecP {
		UiSi.Mul(Si, vecP[i])
		UiSi.Mod(UiSi, pk.Prime)
		Ps.Add(Ps, UiSi)
		Ps.Mod(Ps, pk.Prime)

		ViSi.Mul(Si, vecQ[i])
		ViSi.Mod(ViSi, pk.Prime)
		Qs.Add(Qs, ViSi)
		Qs.Mod(Qs, pk.Prime)

		Si.Mul(Si, secret)
		Si.Mod(Si, pk.Prime)
	}

	return Ps, Qs, nil
}

func (dppk *PrivateKey) Decrypt(Ps *big.Int, Qs *big.Int) (x1, x2 *big.Int, err error) {
	Ps.Add(Ps, dppk.s0a0)
	Ps.Mod(Ps, dppk.PublicKey.Prime)
	Qs.Add(Qs, dppk.s0b0)
	Qs.Mod(Qs, dppk.PublicKey.Prime)

	// As:
	// 	Ps := Bn * (x^2 + a1x + a0) mod p
	// 	Qs := Bn * (x^2 + b1x + b0) mod p
	//
	// We have:
	// 	Ps*revBn(s):= (x^2 + a1x + a0) mod p
	// 	Qs*revBn(s):= (x^2 + b1x + b0) mod p
	//
	// Then:
	// 	Ps* Qs * revBn(s):= (x^2 + a1x + a0) * Qs mod p
	// 	Ps* Qs * revBn(s):= (x^2 + b1x + b0) * Ps mod p
	//
	// Solve this equation to get x
	// 	(x^2 + a1x + a0) * Qs  == (x^2 + b1x + b0) * Ps modp

	// the following procedure will be formalized to :
	// ax^2 + bx + c = 0
	a := new(big.Int)
	revPs := new(big.Int).Sub(dppk.PublicKey.Prime, Ps)
	a.Add(Qs, revPs)
	a.Mod(a, dppk.PublicKey.Prime)

	b := new(big.Int)
	a1Qs := new(big.Int).Mul(Qs, dppk.a1)
	b1Ps := new(big.Int).Mul(Ps, dppk.b1)
	b1Ps.Mod(b1Ps, dppk.PublicKey.Prime)
	revb1Ps := new(big.Int).Sub(dppk.PublicKey.Prime, b1Ps)
	b.Add(a1Qs, revb1Ps)
	b.Mod(b, dppk.PublicKey.Prime)

	c := new(big.Int)
	a0Qs := new(big.Int).Mul(Qs, dppk.a0)
	b0Ps := new(big.Int).Mul(Ps, dppk.b0)
	b0Ps.Mod(b0Ps, dppk.PublicKey.Prime)
	revb0Ps := new(big.Int).Sub(dppk.PublicKey.Prime, b0Ps)
	c.Add(a0Qs, revb0Ps)
	c.Mod(c, dppk.PublicKey.Prime)

	bsquared := new(big.Int).Mul(b, b)
	bsquared.Mod(bsquared, dppk.PublicKey.Prime)

	fourac := new(big.Int).Mul(big.NewInt(4), big.NewInt(0).Mul(a, c))
	fourac.Mod(fourac, dppk.PublicKey.Prime)
	invFourac := new(big.Int).Sub(dppk.PublicKey.Prime, fourac)

	squared := big.NewInt(0).Add(bsquared, invFourac)
	squared.Mod(squared, dppk.PublicKey.Prime)

	// solve quadratic equation
	root := new(big.Int).ModSqrt(squared, dppk.PublicKey.Prime)

	// div 2a
	inv2a := big.NewInt(2)
	inv2a.Mul(inv2a, a)
	inv2a.Mod(inv2a, dppk.PublicKey.Prime)
	inv2a.ModInverse(inv2a, dppk.PublicKey.Prime)

	negb := new(big.Int).Sub(dppk.PublicKey.Prime, b)

	revRoot := new(big.Int).Sub(dppk.PublicKey.Prime, root)
	x1 = big.NewInt(0).Add(negb, revRoot)
	x1.Mod(x1, dppk.PublicKey.Prime)
	x1.Mul(x1, inv2a)
	x1.Mod(x1, dppk.PublicKey.Prime)

	x2 = big.NewInt(0).Add(negb, root)
	x2.Mod(x2, dppk.PublicKey.Prime)
	x2.Mul(x2, inv2a)
	x2.Mod(x2, dppk.PublicKey.Prime)

	return x1, x2, nil
}
