# DPPK
![image](https://github.com/user-attachments/assets/d396d009-1f62-4273-af48-869e388c3445)

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
  - **Classical Attacks**: Super-exponential difficulty $O(p^2)$.
  - **Quantum Attacks**: Exponential difficulty $O(p)$.
- In comparison, the complexity for the Polynomial Factoring Problem (PFP) is:
  - **Classical Attacks**: $O(n\sqrt{p})$.
  - **Quantum Attacks**: $O(\sqrt{p})$, matching the complexity level of Grover’s search algorithm.

# Practical Implementation and Performance

## Keypair Generation and Encryption/Decryption

- The central idea for keypair construction arises from Vieta’s formulas by decoupling the coefficients of a polynomial into two categories:
  - **Private**: From its constant term.
  - **Public**: From the coefficients of the indeterminate $x$.

- DPPK uses two entangled generic polynomials based on a common base polynomial $B_n(x)$ with two solvable polynomials $u(x)$ and $v(x)$:
  - **Public Key**: All coefficients of the entangled polynomials.
  - **Private Key**: Their constant terms and the two solvable polynomials.

## Security Analysis

- **Deterministic Time Complexity**:
  - **Classical Attacks**: $O(\sqrt{p})$ (super-exponential difficulty).
  - **Quantum Attacks**: $O(p)$ (exponential difficulty).
  
## Installation
To install DPPK, use:
```console
go get -u github.com/xtaci/dppk
```

## Examples
#### Keypair Generation
```go
package main

import (
    "github.com/xtaci/dppk"
    "log"
)

func main() {
    // Generate key for Alice
    alice, err := dppk.GenerateKey(10)
    if err != nil {
        log.Fatal(err)
    }

    // Generate key for Bob
    bob, err := dppk.GenerateKey(10)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Alice's Public Key:", alice.PublicKey)
    log.Println("Bob's Public Key:", bob.PublicKey)
}

```

#### Encryption
```go
package main

import (
    "github.com/xtaci/dppk"
    "log"
    "math/big"
)

func main() {
    // Assume alice and bob have already generated their keys
    alice, _ := dppk.GenerateKey(10)
    bob, _ := dppk.GenerateKey(10)

    // Secret message
    secret := new(big.Int).SetBytes([]byte("hello quantum"))

    // Bob encrypts the message for Alice
    kem, err := bob.Encrypt(&alice.PublicKey, secret)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("KEM: %+v\n", kem)
}

```

#### Decryption
```go
package main

import (
    "github.com/xtaci/dppk"
    "log"
)

func main() {
    // Assume alice and bob have already generated their keys and bob has encrypted a message
    alice, _ := dppk.GenerateKey(10)
    bob, _ := dppk.GenerateKey(10)
    secret := new(big.Int).SetBytes([]byte("hello quantum"))
    kem, _ := bob.Encrypt(&alice.PublicKey, secret)

    // Alice decrypts the message
    x1, x2, err := alice.Decrypt(kem)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Decrypted message x1:", x1)
    log.Println("Decrypted message x2:", x2)
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or additional features.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

## References

For more detailed information, please refer to the [research paper](https://www.researchgate.net/profile/Randy-Kuang/publication/358101087_A_Deterministic_Polynomial_Public_Key_Algorithm_over_a_Prime_Galois_Field_GFp/links/61f95ff44393577abe055af7/A-Deterministic-Polynomial-Public-Key-Algorithm-over-a-Prime-Galois-Field-GFp.pdf).

## Acknowledgments

Special thanks to the authors of the research paper for their groundbreaking work on DPPK.
