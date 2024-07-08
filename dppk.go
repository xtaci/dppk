package dppk

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// PRIME is the prime number used in the DPPK protocol.
const PRIME = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637"

// PrivateKey represents a private key in the DPPK protocol.
type PrivateKey struct {
	s0             *big.Int // Initial secret value
	a0, a1, b0, b1 *big.Int // Coefficients for the polynomials
	s0a0, s0b0     *big.Int // Precomputed constant terms of the polynomials
	PublicKey
}

// PublicKey represents a public key in the DPPK protocol.
type PublicKey struct {
	prime *big.Int   // Prime number used in the protocol
	vecU  []*big.Int // Coefficients for polynomial U
	vecQ  []*big.Int // Coefficients for polynomial Q
}

func (pk *PublicKey) GetPrime() *big.Int     { return pk.prime }
func (pk *PublicKey) GetVectorU() []*big.Int { return pk.vecU }
func (pk *PublicKey) GetVectorQ() []*big.Int { return pk.vecQ }

// GenerateKey generates a new DPPK private key with the given order.
func GenerateKey(order int) (*PrivateKey, error) {
	// Ensure the order is at least 5
	if order < 5 {
		return nil, errors.New("order must be at least 5")
	}
	prime, _ := big.NewInt(0).SetString(PRIME, 10)

RETRY:
	// Generate random coefficients for the polynomials
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

	// Ensure all coefficients are distinct
	if a0.Cmp(a1) == 0 || a0.Cmp(b0) == 0 || a0.Cmp(b1) == 0 || a1.Cmp(b0) == 0 || a1.Cmp(b1) == 0 || b0.Cmp(b1) == 0 {
		goto RETRY
	}

	// Generate random coefficients for the polynomial Bn(x)
	Bn := make([]*big.Int, order)
	for i := 0; i < len(Bn); i++ {
		r, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		Bn[i] = r
	}
	// Ensure the coefficient of x^n is 1
	Bn = append(Bn, big.NewInt(1))

	// Initialize vectors for polynomials U(x) and Q(x)
	vecU := make([]*big.Int, order+3)
	vecV := make([]*big.Int, order+3)
	for i := 0; i < order+3; i++ {
		vecU[i] = big.NewInt(0)
		vecV[i] = big.NewInt(0)
	}

	bigInt := new(big.Int)

	// Compute the coefficients for the polynomials U(x) and Q(x) using Vieta's formulas
	for i := 0; i < order+1; i++ {
		// Vector U
		vecU[i].Add(vecU[i], bigInt.Mul(a0, Bn[i]))
		vecU[i].Mod(vecU[i], prime)

		vecU[i+1].Add(vecU[i+1], bigInt.Mul(a1, Bn[i]))
		vecU[i+1].Mod(vecU[i+1], prime)

		vecU[i+2].Add(vecU[i+2], Bn[i])
		vecU[i+2].Mod(vecU[i+2], prime)

		// Vector Q
		vecV[i].Add(vecV[i], bigInt.Mul(b0, Bn[i]))
		vecV[i].Mod(vecV[i], prime)

		vecV[i+1].Add(vecV[i+1], bigInt.Mul(b1, Bn[i]))
		vecV[i+1].Mod(vecV[i+1], prime)

		vecV[i+2].Add(vecV[i+2], Bn[i])
		vecV[i+2].Mod(vecV[i+2], prime)
	}

	// Create the private key
	priv := &PrivateKey{
		s0:   Bn[0],
		a0:   a0,
		a1:   a1,
		b0:   b0,
		b1:   b1,
		s0a0: vecU[0],
		s0b0: vecV[0],
	}

	// Set the public key vectors, excluding the first and last elements
	priv.PublicKey.vecU = vecU[1 : order+2]
	priv.PublicKey.vecQ = vecV[1 : order+2]
	priv.PublicKey.prime = prime
	return priv, nil
}

// Encrypt encrypts a message using the given public key.
func (dppk *PrivateKey) Encrypt(pk *PublicKey, msg []byte) (Ps *big.Int, Qs *big.Int, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(msg)
	if secret.Cmp(dppk.PublicKey.prime) >= 0 {
		return nil, nil, errors.New("data is too large")
	}

	// Extend the vectors U and Q with a constant term of 1
	vecUExt := make([]*big.Int, len(dppk.PublicKey.vecU)+1)
	vecQExt := make([]*big.Int, len(dppk.PublicKey.vecQ)+1)
	copy(vecUExt, pk.vecU)
	copy(vecQExt, pk.vecQ)
	vecUExt[len(vecUExt)-1] = big.NewInt(1)
	vecQExt[len(vecQExt)-1] = big.NewInt(1)

	// Initialize variables for the encryption process
	Ps = big.NewInt(0)
	Qs = big.NewInt(0)
	Si := new(big.Int).Set(secret)
	UiSi := new(big.Int)
	ViSi := new(big.Int)

	// Compute the encrypted values Ps and Qs
	for i := range vecUExt {
		UiSi.Mul(Si, vecUExt[i])
		UiSi.Mod(UiSi, pk.prime)
		Ps.Add(Ps, UiSi)
		Ps.Mod(Ps, pk.prime)

		ViSi.Mul(Si, vecQExt[i])
		ViSi.Mod(ViSi, pk.prime)
		Qs.Add(Qs, ViSi)
		Qs.Mod(Qs, pk.prime)

		Si.Mul(Si, secret)
		Si.Mod(Si, pk.prime)
	}

	return Ps, Qs, nil
}

// Decrypt decrypts the encrypted values Ps and Qs using the private key.
func (dppk *PrivateKey) Decrypt(Ps *big.Int, Qs *big.Int) (x1, x2 *big.Int, err error) {
	// Adjust Ps and Qs with precomputed constant terms
	_Ps := new(big.Int).Set(Ps)
	_Qs := new(big.Int).Set(Qs)
	_Ps.Add(_Ps, dppk.s0a0)
	_Ps.Mod(_Ps, dppk.PublicKey.prime)
	_Qs.Add(_Qs, dppk.s0b0)
	_Qs.Mod(_Qs, dppk.PublicKey.prime)

	// As:
	//      Ps := Bn * (x^2 + a1x + a0) mod p
	//      Qs := Bn * (x^2 + b1x + b0) mod p
	//
	// We have:
	//      Ps*revBn(s):= (x^2 + a1x + a0) mod p
	//      Qs*revBn(s):= (x^2 + b1x + b0) mod p
	//
	// Then:
	//      Ps* Qs * revBn(s):= (x^2 + a1x + a0) * Qs mod p
	//      Ps* Qs * revBn(s):= (x^2 + b1x + b0) * Ps mod p
	//
	// Solve this equation to get x
	//      (x^2 + a1x + a0) * Qs  == (x^2 + b1x + b0) * Ps modp
	// the following procedure will be formalized to :
	// ax^2 + bx + c = 0

	a := new(big.Int)
	revPs := new(big.Int).Sub(dppk.PublicKey.prime, _Ps)
	a.Add(_Qs, revPs)
	a.Mod(a, dppk.PublicKey.prime)

	b := new(big.Int)
	a1Qs := new(big.Int).Mul(_Qs, dppk.a1)
	b1Ps := new(big.Int).Mul(_Ps, dppk.b1)
	b1Ps.Mod(b1Ps, dppk.PublicKey.prime)
	revb1Ps := new(big.Int).Sub(dppk.PublicKey.prime, b1Ps)
	b.Add(a1Qs, revb1Ps)
	b.Mod(b, dppk.PublicKey.prime)

	c := new(big.Int)
	a0Qs := new(big.Int).Mul(_Qs, dppk.a0)
	b0Ps := new(big.Int).Mul(_Ps, dppk.b0)
	b0Ps.Mod(b0Ps, dppk.PublicKey.prime)
	revb0Ps := new(big.Int).Sub(dppk.PublicKey.prime, b0Ps)
	c.Add(a0Qs, revb0Ps)
	c.Mod(c, dppk.PublicKey.prime)

	// Solve the quadratic equation derived from Ps and Qs
	// Compute the discriminant of the quadratic equation
	bsquared := new(big.Int).Mul(b, b)
	bsquared.Mod(bsquared, dppk.PublicKey.prime)

	fourac := new(big.Int).Mul(big.NewInt(4), big.NewInt(0).Mul(a, c))
	fourac.Mod(fourac, dppk.PublicKey.prime)
	invFourac := new(big.Int).Sub(dppk.PublicKey.prime, fourac)

	squared := big.NewInt(0).Add(bsquared, invFourac)
	squared.Mod(squared, dppk.PublicKey.prime)

	// Solve the quadratic equation
	root := new(big.Int).ModSqrt(squared, dppk.PublicKey.prime)

	// Calculate the roots of the equation
	inv2a := big.NewInt(2)
	inv2a.Mul(inv2a, a)
	inv2a.Mod(inv2a, dppk.PublicKey.prime)
	inv2a.ModInverse(inv2a, dppk.PublicKey.prime)

	negb := new(big.Int).Sub(dppk.PublicKey.prime, b)

	revRoot := new(big.Int).Sub(dppk.PublicKey.prime, root)
	x1 = big.NewInt(0).Add(negb, revRoot)
	x1.Mod(x1, dppk.PublicKey.prime)
	x1.Mul(x1, inv2a)
	x1.Mod(x1, dppk.PublicKey.prime)

	x2 = big.NewInt(0).Add(negb, root)
	x2.Mod(x2, dppk.PublicKey.prime)
	x2.Mul(x2, inv2a)
	x2.Mod(x2, dppk.PublicKey.prime)

	return x1, x2, nil
}
