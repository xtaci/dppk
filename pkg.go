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
