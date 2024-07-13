// Package dppk implements the Deterministic Polynomial Public Key (DPPK) algorithm.
//
// The ancient Vieta’s formulas reveal the relationships
// between coefficients of an nth-degree polynomial and its roots. It is
// surprisingly found that there exists a hidden secret for a potential
// public key exchange: decoupling the product of all roots or constant
// term from summations of root products or coefficients of a polynomial
// to establish a keypair. The proposed deterministic polynomial public
// key algorithm or DPPK is built on the fact that a polynomial cannot be
// factorized without its constant term.
//
// DPPK allows the keypair generator to combine a base polynomial,
// eliminable during the decryption, with two solvable polynomials
// and creates two entangled polynomials. Two coefficient vectors of the
// entangled polynomials form a public key, and their constant terms,
// together with the two solvable polynomials, form the private key.
// By only publishing coefficients of polynomials without their constant
// terms, we greatly restrict polynomial factoring techniques for the private
// key extraction.
package dppk

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// DefaultPrime is the default prime number used in the DPPK protocol.
const DefaultPrime = "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596231637"

const (
	ERR_MSG_ORDER         = "order must be at least 5"
	ERR_MSG_NULL_ENCRYPT  = "encrypted values cannot be null"
	ERR_MSG_DATA_EXCEEDED = "the secret to encrypt is not in the GF(p)"
	ERR_MSG_VU_PUBLICKEY  = "VU in public key is not equal"
)

// PrivateKey represents a private key in the DPPK protocol.
type PrivateKey struct {
	S0             *big.Int // Initial secret value
	A0, A1, B0, B1 *big.Int // Coefficients for the polynomials
	Prime          *big.Int // Prime number used in this private key
	PublicKey
}

// PublicKey represents a public key in the DPPK protocol.
type PublicKey struct {
	VectorU []*big.Int // Coefficients for polynomial U
	VectorV []*big.Int // Coefficients for polynomial V
}

// Equal checks if two public keys are equal.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if len(pub.VectorU) != len(other.VectorU) {
		return false
	}

	if len(pub.VectorV) != len(other.VectorV) {
		return false
	}

	for i := range pub.VectorU {
		if pub.VectorU[i].Cmp(other.VectorU[i]) != 0 {
			return false
		}
	}

	for i := range pub.VectorV {
		if pub.VectorV[i].Cmp(other.VectorV[i]) != 0 {
			return false
		}
	}

	return true
}

// Order returns the order of the public key.
func (pub *PublicKey) Order() int {
	return len(pub.VectorU) - 1
}

// GenerateKey generates a new DPPK private key with the given order and prime number
// the prime number is a string formatted in base 10
func GenerateKeyWithPrime(order int, prime string) (*PrivateKey, error) {
	return generateKey(order, prime)
}

// GenerateKey generates a new DPPK private key with the given order and default prime number
func GenerateKey(order int) (*PrivateKey, error) {
	return generateKey(order, DefaultPrime)
}

// GenerateKey generates a new DPPK private key with the given order.
func generateKey(order int, strPrime string) (*PrivateKey, error) {
	// Ensure the order is at least 5
	if order < 5 {
		return nil, errors.New(ERR_MSG_ORDER)
	}
	prime, _ := big.NewInt(0).SetString(strPrime, 10)

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

	// Initialize vectors for polynomials U(x) and V(x)
	vecU := make([]*big.Int, order+3)
	vecV := make([]*big.Int, order+3)
	for i := 0; i < order+3; i++ {
		vecU[i] = big.NewInt(0)
		vecV[i] = big.NewInt(0)
	}

	bigInt := new(big.Int)

	// Compute the coefficients for the polynomials U(x) and V(x) using Vieta's formulas
	for i := 0; i < order+1; i++ {
		// Vector U
		vecU[i].Add(vecU[i], bigInt.Mul(a0, Bn[i]))
		vecU[i].Mod(vecU[i], prime)

		vecU[i+1].Add(vecU[i+1], bigInt.Mul(a1, Bn[i]))
		vecU[i+1].Mod(vecU[i+1], prime)

		vecU[i+2].Add(vecU[i+2], Bn[i])
		vecU[i+2].Mod(vecU[i+2], prime)

		// Vector V
		vecV[i].Add(vecV[i], bigInt.Mul(b0, Bn[i]))
		vecV[i].Mod(vecV[i], prime)

		vecV[i+1].Add(vecV[i+1], bigInt.Mul(b1, Bn[i]))
		vecV[i+1].Mod(vecV[i+1], prime)

		vecV[i+2].Add(vecV[i+2], Bn[i])
		vecV[i+2].Mod(vecV[i+2], prime)
	}

	// Create the private key
	priv := &PrivateKey{
		S0:    Bn[0],
		A0:    a0,
		A1:    a1,
		B0:    b0,
		B1:    b1,
		Prime: prime,
	}

	// Set the public key vectors, excluding the first and last elements
	priv.PublicKey.VectorU = vecU[1 : order+2]
	priv.PublicKey.VectorV = vecV[1 : order+2]
	return priv, nil
}

// encrypt encrypts a message with the given public key and custom prime
func EncryptWithPrime(pub *PublicKey, msg []byte, prime *big.Int) (Ps *big.Int, Qs *big.Int, err error) {
	return encrypt(pub, msg, prime)
}

// encrypt encrypts a message with the given public key and default prime
func Encrypt(pub *PublicKey, msg []byte) (Ps *big.Int, Qs *big.Int, err error) {
	prime, _ := big.NewInt(0).SetString(DefaultPrime, 10)
	return encrypt(pub, msg, prime)
}

// encrypt encrypts a message with the given public key.
func encrypt(pub *PublicKey, msg []byte, prime *big.Int) (Ps *big.Int, Qs *big.Int, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(msg)
	if secret.Cmp(prime) >= 0 {
		return nil, nil, errors.New(ERR_MSG_DATA_EXCEEDED)
	}

	if len(pub.VectorU) != len(pub.VectorV) {
		return nil, nil, errors.New(ERR_MSG_VU_PUBLICKEY)
	}

	// Ensure the values in the public key are not nil
	for i := range pub.VectorU {
		if pub.VectorU[i] == nil {
			return nil, nil, errors.New(ERR_MSG_VU_PUBLICKEY)
		}

		if pub.VectorV[i] == nil {
			return nil, nil, errors.New(ERR_MSG_VU_PUBLICKEY)
		}
	}

	// Extend the vectors U and Q with a constant term of 1
	vecUExt := make([]*big.Int, len(pub.VectorU)+1)
	vecVExt := make([]*big.Int, len(pub.VectorV)+1)
	copy(vecUExt, pub.VectorU)
	copy(vecVExt, pub.VectorV)
	vecUExt[len(vecUExt)-1] = big.NewInt(1)
	vecVExt[len(vecVExt)-1] = big.NewInt(1)

	// Initialize variables for the encryption process
	Ps = big.NewInt(0)
	Qs = big.NewInt(0)
	Si := new(big.Int).Set(secret)
	UiSi := new(big.Int)
	ViSi := new(big.Int)

	// Compute the encrypted values Ps and Qs
	for i := range vecUExt {
		UiSi.Mul(Si, vecUExt[i])
		UiSi.Mod(UiSi, prime)
		Ps.Add(Ps, UiSi)
		Ps.Mod(Ps, prime)

		ViSi.Mul(Si, vecVExt[i])
		ViSi.Mod(ViSi, prime)
		Qs.Add(Qs, ViSi)
		Qs.Mod(Qs, prime)

		Si.Mul(Si, secret)
		Si.Mod(Si, prime)
	}

	return Ps, Qs, nil
}

// Decrypt decrypts the encrypted values Ps and Qs using the private key.
func (priv *PrivateKey) Decrypt(Ps *big.Int, Qs *big.Int) (x1, x2 *big.Int, err error) {
	if Ps == nil || Qs == nil {
		return nil, nil, errors.New(ERR_MSG_NULL_ENCRYPT)
	}

	prime := priv.Prime

	// Add constant term to get full Ps and Qs polynomial
	polyP := new(big.Int).Set(Ps)
	polyQ := new(big.Int).Set(Qs)

	s0a0 := new(big.Int)
	s0b0 := new(big.Int)
	s0a0.Mul(priv.S0, priv.A0)
	s0a0.Mod(s0a0, prime)
	s0b0.Mul(priv.S0, priv.B0)
	s0b0.Mod(s0b0, prime)

	polyP.Add(polyP, s0a0)
	polyP.Mod(polyP, prime)
	polyQ.Add(polyQ, s0b0)
	polyQ.Mod(polyQ, prime)

	// Explanation:
	// As:
	//      Ps := Bn * (x^2 + a1x + a0) mod p
	//      Qs := Bn * (x^2 + b1x + b0) mod p
	//
	// multiply the reverse of Bn on the both side of the equation, we have:
	//      Ps*revBn(s):= (x^2 + a1x + a0) mod p
	//      Qs*revBn(s):= (x^2 + b1x + b0) mod p
	//
	// to align the left and right side of the equation, we have:
	//      Ps* Qs * revBn(s):= (x^2 + a1x + a0) * Qs mod p
	//      Ps* Qs * revBn(s):= (x^2 + b1x + b0) * Ps mod p
	//
	// and evidently:
	//      (x^2 + a1x + a0) * Qs  == (x^2 + b1x + b0) * Ps modp
	//
	// Solve this equation to get x
	// the following procedure will be formalized to :
	// ax^2 + bx + c = 0

	a := new(big.Int)
	revPs := new(big.Int).Sub(prime, polyP)
	a.Add(polyQ, revPs)
	a.Mod(a, priv.Prime)

	b := new(big.Int)
	a1Qs := new(big.Int).Mul(polyQ, priv.A1)
	b1Ps := new(big.Int).Mul(polyP, priv.B1)
	b1Ps.Mod(b1Ps, priv.Prime)
	revb1Ps := new(big.Int).Sub(prime, b1Ps)
	b.Add(a1Qs, revb1Ps)
	b.Mod(b, priv.Prime)

	c := new(big.Int)
	a0Qs := new(big.Int).Mul(polyQ, priv.A0)
	b0Ps := new(big.Int).Mul(polyP, priv.B0)
	b0Ps.Mod(b0Ps, priv.Prime)
	revb0Ps := new(big.Int).Sub(prime, b0Ps)
	c.Add(a0Qs, revb0Ps)
	c.Mod(c, priv.Prime)

	// Solve the quadratic equation derived from Ps and Qs
	// Compute the discriminant of the quadratic equation
	bsquared := new(big.Int).Mul(b, b)
	bsquared.Mod(bsquared, prime)

	fourac := new(big.Int).Mul(big.NewInt(4), big.NewInt(0).Mul(a, c))
	fourac.Mod(fourac, prime)
	invFourac := new(big.Int).Sub(prime, fourac)

	squared := big.NewInt(0).Add(bsquared, invFourac)
	squared.Mod(squared, prime)

	// Solve the quadratic equation
	root := new(big.Int).ModSqrt(squared, prime)

	// Calculate the roots of the equation
	inv2a := big.NewInt(2)
	inv2a.Mul(inv2a, a)
	inv2a.Mod(inv2a, prime)
	inv2a.ModInverse(inv2a, prime)

	negb := new(big.Int).Sub(prime, b)

	revRoot := new(big.Int).Sub(prime, root)
	x1 = big.NewInt(0).Add(negb, revRoot)
	x1.Mod(x1, prime)
	x1.Mul(x1, inv2a)
	x1.Mod(x1, prime)

	x2 = big.NewInt(0).Add(negb, root)
	x2.Mod(x2, prime)
	x2.Mul(x2, inv2a)
	x2.Mod(x2, prime)

	return x1, x2, nil
}

// Public returns the public key of the private key.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}
