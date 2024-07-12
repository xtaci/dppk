# DPPK

![image](https://github.com/xtaci/dppk/assets/2346725/33680bad-7a91-48a8-ad56-fbd3ac96aeaf)


[![GoDoc][1]][2] [![Go Report Card][3]][4]

[1]: https://godoc.org/github.com/xtaci/dppk?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/dppk
[3]: https://goreportcard.com/badge/github.com/xtaci/dppk
[4]: https://goreportcard.com/report/github.com/xtaci/dppk

[A Deterministic Polynomial Public Key Algorithm over a Prime Galois Field GF(p)](https://www.researchgate.net/profile/Randy-Kuang/publication/358101087_A_Deterministic_Polynomial_Public_Key_Algorithm_over_a_Prime_Galois_Field_GFp/links/61f95ff44393577abe055af7/A-Deterministic-Polynomial-Public-Key-Algorithm-over-a-Prime-Galois-Field-GFp.pdf)

DPPK is an [Key encapsulation mechanism](https://en.wikipedia.org/wiki/Key_encapsulation_mechanism), a.k.a. - KEM

# Overview

The ancient [Vieta’s formulas](https://en.wikipedia.org/wiki/Vieta%27s_formulas) reveal the relationships between the coefficients of an nth-degree polynomial and its roots. It has been surprisingly found that there exists a hidden secret for a potential public key exchange: decoupling the product of all roots (or the constant term) from the summations of root products (or coefficients) of a polynomial to establish a keypair.

# Proposed Algorithm: Deterministic Polynomial Public Key (DPPK)

## Key Principles

1. **Factorization Dependency**: The DPPK algorithm is built on the fact that a polynomial cannot be factorized without its constant term.
2. **Keypair Construction**: The keypair generator combines a base polynomial, which can be eliminated during decryption, with two solvable polynomials to create two entangled polynomials.
   - **Public Key**: Formed by the coefficient vectors of the entangled polynomials.
   - **Private Key**: Composed of the constant terms of the entangled polynomials and the two solvable polynomials.

## Security Mechanism

- By only publishing the coefficients of the polynomials without their constant terms, polynomial factoring techniques for private key extraction are greatly restricted.
- The time complexity for private key extraction from the public key is:
  - **Classical Attacks**: Super-exponential difficulty \(O(p^2)\).
  - **Quantum Attacks**: Exponential difficulty \(O(p)\).
- In comparison, the complexity for the Polynomial Factoring Problem (PFP) is:
  - **Classical Attacks**: \(O(np^{1/2})\).
  - **Quantum Attacks**: \(O(p^{1/2})\), matching the complexity level of Grover’s search algorithm.

# Practical Implementation and Performance

## Keypair Generation and Encryption/Decryption

- The central idea for keypair construction arises from Vieta’s formulas by decoupling the coefficients of a polynomial into two categories:
  - **Private**: From its constant term.
  - **Public**: From the coefficients of the indeterminate \(x\).

- DPPK uses two entangled generic polynomials based on a common base polynomial \(B_n(x)\) with two solvable polynomials \(u(x)\) and \(v(x)\):
  - **Public Key**: All coefficients of the entangled polynomials.
  - **Private Key**: Their constant terms and the two solvable polynomials.

## Security Analysis

- **Deterministic Time Complexity**:
  - **Classical Attacks**: \(O(p^2)\) (super-exponential difficulty).
  - **Quantum Attacks**: \(O(p)\) (exponential difficulty).

- **Comparison with PQC Algorithms**: DPPK demonstrates a higher security level with a complexity \(O(p^{1/2})\) for secret key extraction, offering the same security level as AES-256.

# Usage
```golang
func TestDPPK(t *testing.T) {
	alice, err := GenerateKey(10)
	assert.Nil(t, err)

	secret := []byte("hello quantum")
	Ps, Qs, err := Encrypt(&alice.PublicKey, secret)
	assert.Nil(t, err)
	t.Log("secret:", string(secret))

	x1, x2, err := alice.Decrypt(Ps, Qs)
	assert.Nil(t, err)
	t.Log("x1:", string(x1.Bytes()))
	t.Log("x2:", string(x2.Bytes()))

	equal := bytes.Equal(secret, x1.Bytes()) || bytes.Equal(secret, x2.Bytes())
	assert.True(t, equal)
}
```
