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
	"crypto/rand"
	"errors"
	"math/big"
)

// DefaultPrime is the default prime number used in the DPPK protocol.
const DefaultPrime = "0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d5"

const (
	ERR_MSG_ORDER         = "order must be at least 5"
	ERR_MSG_NULL_ENCRYPT  = "encrypted values cannot be null"
	ERR_MSG_DATA_EXCEEDED = "the secret to encrypt is not in the GF(p)"
	ERR_MSG_VU_PUBLICKEY  = "VU in public key is not equal"
)

const secretMarker = "\x5f\x37\x59\xdf"

// defaultPrime is the prime number used in cryptographic operations.
var defaultPrime *big.Int
var (
	errInvalidPrime        = errors.New("Invalid Prime")
	errNoQuadraticResidue  = errors.New("ciphertext is not a quadratic residue")
	errSingularQuadratic   = errors.New("no modular inverse for quadratic coefficient")
	errInvalidSecretFormat = errors.New("invalid secret encoding")
)

func init() {
	defaultPrime, _ = new(big.Int).SetString(DefaultPrime, 0)
}

// PrivateKey represents a private key in the DPPK protocol.
type PrivateKey struct {
	S0             *big.Int // Initial secret value
	A0, A1, B0, B1 *big.Int // Coefficients for the polynomials
	PublicKey
}

// PublicKey represents a public key in the DPPK protocol.
type PublicKey struct {
	Prime   *big.Int
	VectorU []*big.Int // Coefficients for polynomial U
	VectorV []*big.Int // Coefficients for polynomial V
}

// KEM represents a Key Encapsulation Mechanism in the DPPK protocol.
type KEM struct {
	Ps *big.Int
	Qs *big.Int
}

// Equal checks if two public keys are equal.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if pub == nil || other == nil {
		return false
	}

	if (pub.Prime == nil) != (other.Prime == nil) {
		return false
	}

	if pub.Prime != nil && pub.Prime.Cmp(other.Prime) != 0 {
		return false
	}

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
func GenerateKeyWithPrime(order int, strPrime string) (*PrivateKey, error) {
	customPrime, ok := big.NewInt(0).SetString(strPrime, 0)
	if !ok {
		return nil, errInvalidPrime
	}
	return generateKey(order, customPrime)
}

// GenerateKey generates a new DPPK private key with the given order and default prime number
func GenerateKey(order int) (*PrivateKey, error) {
	return generateKey(order, defaultPrime)
}

// GenerateKey generates a new DPPK private key with the given order.
func generateKey(order int, prime *big.Int) (*PrivateKey, error) {
	// Ensure the order is at least 5
	if order < 5 {
		return nil, errors.New(ERR_MSG_ORDER)
	}

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
		S0: Bn[0],
		A0: a0,
		A1: a1,
		B0: b0,
		B1: b1,
	}

	// Set the public key vectors, excluding the first and last elements
	priv.Prime = prime
	priv.PublicKey.VectorU = vecU[1 : order+2]
	priv.PublicKey.VectorV = vecV[1 : order+2]
	return priv, nil
}

// encrypt encrypts a message with the given public key and the prime specified in public key

func encodeSecret(msg []byte) []byte {
	encoded := make([]byte, len(msg)+len(secretMarker))
	copy(encoded, secretMarker)
	copy(encoded[len(secretMarker):], msg)
	return encoded
}

func Encrypt(pub *PublicKey, msg []byte) (kem *KEM, err error) {
	return encrypt(pub, msg, pub.Prime)
}

// encrypt encrypts a message with the given public key.
func encrypt(pub *PublicKey, msg []byte, prime *big.Int) (kem *KEM, err error) {
	// Convert the message to a big integer
	secret := new(big.Int).SetBytes(encodeSecret(msg))
	if secret.Cmp(prime) >= 0 {
		return nil, errors.New(ERR_MSG_DATA_EXCEEDED)
	}

	if len(pub.VectorU) != len(pub.VectorV) {
		return nil, errors.New(ERR_MSG_VU_PUBLICKEY)
	}

	// Ensure the values in the public key are not nil
	for i := range pub.VectorU {
		if pub.VectorU[i] == nil {
			return nil, errors.New(ERR_MSG_VU_PUBLICKEY)
		}

		if pub.VectorV[i] == nil {
			return nil, errors.New(ERR_MSG_VU_PUBLICKEY)
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
	Ps := big.NewInt(0)
	Qs := big.NewInt(0)
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

	return &KEM{Ps: Ps, Qs: Qs}, nil
}

// Decrypt decrypts the encrypted values Ps and Qs using the private key.
func (priv *PrivateKey) Decrypt(kem *KEM) (x1, x2 *big.Int, err error) {
	if kem == nil {
		return nil, nil, errors.New(ERR_MSG_NULL_ENCRYPT)
	}

	Ps := kem.Ps
	Qs := kem.Qs
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
	if root == nil {
		return nil, nil, errNoQuadraticResidue
	}

	// Calculate the roots of the equation
	doubleA := new(big.Int).Mul(big.NewInt(2), a)
	doubleA.Mod(doubleA, prime)
	inv2a := new(big.Int).ModInverse(doubleA, prime)
	if inv2a == nil {
		return nil, nil, errSingularQuadratic
	}

	negb := new(big.Int).Sub(prime, b)

	// Solve the quadratic equation:
	//
	//          -b + sqrt(b^2 - 4ac)
	//   x1 =   ---------------------
	//                  2a
	//
	//          -b - sqrt(b^2 - 4ac)
	//   x2 =   ---------------------
	//                  2a
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

// DecryptMessage returns the plaintext message embedded in the ciphertext.
// It tries both candidate roots and returns the first one that matches the
// expected secret encoding marker.
func (priv *PrivateKey) DecryptMessage(kem *KEM) ([]byte, error) {
	x1, x2, err := priv.Decrypt(kem)
	if err != nil {
		return nil, err
	}

	if msg, err := RecoverMessage(x1); err == nil {
		return msg, nil
	}

	if msg, err := RecoverMessage(x2); err == nil {
		return msg, nil
	}

	return nil, errInvalidSecretFormat
}

// RecoverMessage converts a decrypted root into the original plaintext.
func RecoverMessage(candidate *big.Int) ([]byte, error) {
	if candidate == nil {
		return nil, errInvalidSecretFormat
	}

	raw := candidate.Bytes()
	if len(raw) < len(secretMarker) || string(raw[:len(secretMarker)]) != secretMarker {
		return nil, errInvalidSecretFormat
	}

	msg := make([]byte, len(raw)-len(secretMarker))
	copy(msg, raw[len(secretMarker):])
	return msg, nil
}

// Public returns the public key of the private key.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}
