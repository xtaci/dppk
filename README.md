# DPPK
[A Deterministic Polynomial Public Key Algorithm over a Prime Galois Field GF(p)](https://www.researchgate.net/profile/Randy-Kuang/publication/358101087_A_Deterministic_Polynomial_Public_Key_Algorithm_over_a_Prime_Galois_Field_GFp/links/61f95ff44393577abe055af7/A-Deterministic-Polynomial-Public-Key-Algorithm-over-a-Prime-Galois-Field-GFp.pdf)

# Examples
```golang
func TestDPPK(t *testing.T) {
    dppk, err := GenerateKey(5)
    assert.Nil(t, err)

    secret := []byte("hello quantum")
    Ps, Qs, err := dppk.Encrypt(&dppk.PublicKey, secret)
    assert.Nil(t, err)
    t.Log("secret:", string(secret))

    x1, x2, err := dppk.Decrypt(Ps, Qs)
    t.Log("x1:", string(x1.Bytes()))
    t.Log("x2:", string(x2.Bytes()))

    equal := bytes.Equal(secret, x1.Bytes()) || bytes.Equal(secret, x2.Bytes())
    assert.True(t, equal)
}
```
