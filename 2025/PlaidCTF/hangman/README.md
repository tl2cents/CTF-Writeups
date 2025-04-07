
## Writeup(TODO)

Only the crypto part: pre-image attack on the given hash function.

Note that sbox-1 is actually linear sbox. The step of `res[j] ^= sbox0[...]` is not linear. However, we can just treat the this step as a lookup operation, i.e., T[i, j, payload[j]].Let the left affine transformation be: f(x) = Ax + b over F2. The whole hash is 'affine' as follows:
- Change the single byte in index j1 of payload to a1 will independently change the output by delta_j1.
- Change the single byte in index j2 of payload to a2 will independently change the output by delta_j2.
- Change the bytes in index j1 and j2 of payload to (a1, a2) will change the output by xor(delta_j1, delta_j2).

This affine property easily extends to multiple blocks and allows us to solve linear equations over F2 to find the preimage of any hash value as long as len(payload) >= 128.