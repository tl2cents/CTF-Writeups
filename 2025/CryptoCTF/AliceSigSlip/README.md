
## Writeup

> Solved by me and [deebato](https://github.com/D33BaT0).

I will only explain the hard part of the case 2 where we need to find a signature in form of $(m, r, s, Q) = (m, *, s, *)$. 

The signing process of ED25519:

``` python
# https://github.com/Legrandin/pycryptodome/blob/2c3a8905a7929335a9b2763e18d6e9ed516b8a38/lib/Crypto/Signature/eddsa.py#L158
def _sign_ed25519(self, msg_or_hash, ph):

    if self._context or ph:
        flag = int(ph)
        # dom2(flag, self._context)
        dom2 = b'SigEd25519 no Ed25519 collisions' + bchr(flag) + \
                bchr(len(self._context)) + self._context
    else:
        dom2 = b''

    PHM = msg_or_hash.digest() if ph else msg_or_hash

    # See RFC 8032, section 5.1.6

    # Step 2
    r_hash = SHA512.new(dom2 + self._key._prefix + PHM).digest()
    r = Integer.from_bytes(r_hash, 'little') % self._order
    # Step 3
    R_pk = EccKey(point=r * self._key._curve.G)._export_eddsa_public()
    # Step 4
    k_hash = SHA512.new(dom2 + R_pk + self._A + PHM).digest()
    k = Integer.from_bytes(k_hash, 'little') % self._order
    # Step 5
    s = (r + k * self._key.d) % self._order

    return R_pk + s.to_bytes(32, 'little')
```

The verification of ED25519 signature:

``` python
# https://github.com/Legrandin/pycryptodome/blob/2c3a8905a7929335a9b2763e18d6e9ed516b8a38/lib/Crypto/Signature/eddsa.py#L244
def _verify_ed25519(self, msg_or_hash, signature, ph):

    if len(signature) != 64:
        raise ValueError("The signature is not authentic (length)")

    if self._context or ph:
        flag = int(ph)
        dom2 = b'SigEd25519 no Ed25519 collisions' + bchr(flag) + \
                bchr(len(self._context)) + self._context
    else:
        dom2 = b''

    PHM = msg_or_hash.digest() if ph else msg_or_hash

    # Section 5.1.7

    # Step 1
    try:
        R = import_public_key(signature[:32]).pointQ
    except ValueError:
        raise ValueError("The signature is not authentic (R)")
    s = Integer.from_bytes(signature[32:], 'little')
    if s > self._order:
        raise ValueError("The signature is not authentic (S)")
    # Step 2
    k_hash = SHA512.new(dom2 + signature[:32] + self._A + PHM).digest()
    k = Integer.from_bytes(k_hash, 'little') % self._order
    # Step 3
    point1 = s * 8 * self._key._curve.G
    # OPTIMIZE: with double-scalar multiplication, with no SCA
    # countermeasures because it is public values
    point2 = 8 * R + k * 8 * self._key.pointQ
    if point1 != point2:
        raise ValueError("The signature is not authentic")
```

This actually checks if:

$$
s \cdot 8 \cdot G = 8 \cdot R + k \cdot 8 \cdot Q
$$

If we submit the public key $Q$ as a point of order 8, then we only need to find $R$ such that:

$$
s \cdot 8 \cdot G = 8 \cdot R
$$


From [neuromancer.sk](https://neuromancer.sk/std/other/Ed25519), we know that the curve order is $8p$ which makes the weak public key attack feasible. Luckily, the implementation of ED25519 in `PyCryptodome` does not check such weak public keys. The remaining part is trivial. 

> I find that `PyCryptodome` checks weak points of order 8 on the `Curve25519` in [_validate_x25519_point](https://github.com/Legrandin/pycryptodome/blob/2c3a8905a7929335a9b2763e18d6e9ed516b8a38/lib/Crypto/PublicKey/_montgomery.py#L36). Why does it not check the weak points of order 8 in `ED25519`?