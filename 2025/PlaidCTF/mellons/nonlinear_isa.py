""" 
Implementation of https://eprint.iacr.org/2016/732.pdf
- Weak Distinguish Attack
- Known-Ciphertext Attack of CBC Mode
"""

from sage.all import BooleanPolynomialRing, Sequence


def compress(message_bytes: bytes) -> list[int]:
    """ 
    Compresses a ascii byte array (removes the MSB of each byte) into a list of nibbles.
    Each byte is represented by 7 bits, and the result is padded to a multiple of 8 bits.
    """
    output = []
    for b in message_bytes:
        assert b & 0x80 == 0
        output.append(format(b, '07b'))
    output_str = ''.join(output)
    if len(output_str) % 8 != 0:
        output_str += '0' * (8 - (len(output_str) % 8))
    res = []
    for i in range(0, len(output_str), 8):
        res.append(int(output_str[i:i+8], 2))
    return res

def compress_to_bits_without_pad(message_bytes: bytes) -> list[int]:
    """ 
    Compresses a ascii byte array (removes the MSB of each byte) into a list of nibbles.
    """
    output = []
    for b in message_bytes:
        assert b & 0x80 == 0
        output.append(format(b, '07b'))
    output_str = ''.join(output)
    return [int(i) for i in output_str]

def decompress(message_bytes):
    """
    Decompresses a list of bytes into a byte array.
    Each byte is formed by combining 7 bits from the input (the remaining zeros are ignored).
    """
    bits = []
    for b in message_bytes:
        bits.append(format(b, '08b'))
    bitstr = ''.join(bits)
    bitstr = bitstr[:-(len(bitstr) % 7)]
    output = []
    for i in range(0, len(bitstr), 7):
        output.append(int(bitstr[i:i+7], 2))
    return output

def xor(a, b):
    """
    XORs two byte arrays of the same length.
    """
    assert len(a) == len(b)
    return bytes([a[i] ^ b[i] for i in range(len(a))])

def sym_xor(a, b):
    assert len(a) == len(b)
    return [a[i] + b[i] for i in range(len(a))]

def split_unlinean_invariants(vec: list):
    assert len(vec) == 64
    linear_part = [0] * 64
    nonlinear_part = [0] * 64
    for i in range(0, 64, 4):
        linear_part[i] = vec[i]
        linear_part[i + 1] = vec[i + 1]
        nonlinear_part[i + 2] = vec[i + 2]
        nonlinear_part[i + 3] = vec[i + 3]
    return linear_part, nonlinear_part

bool_poly_ring = BooleanPolynomialRing(4, 'x')
x0, x1, x2, x3 = bool_poly_ring.gens()
S = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
     0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

sbox_nonlinear_invariants = [
    x0 * x3 + x0 + x2 * x3 + x3,
    x0 * x3 + x1 + x2 + x3,
    x0 * x1 + x1 * x2 + x2 * x3 + x2,
    x0 * x2 + x0 * x3]

def check_nonlinear_invariants():
    for invariant_poly in sbox_nonlinear_invariants:
        consts = []
        for inp, out in enumerate(S):
            inp_bits = [int(b) for b in bin(inp)[2:].zfill(4)][::-1]
            out_bits = [int(b) for b in bin(out)[2:].zfill(4)][::-1]
            invariant_poly_value = invariant_poly(*inp_bits) + invariant_poly(*out_bits)
            consts.append(invariant_poly_value)
        assert len(set(consts)) == 1, f"Invariant polynomial {consts = } is not invariant for all inputs."
        print(f"Invariant polynomial {invariant_poly} is invariant with const = {consts[0]}.")  

# we choose g = g[0] + g[1] = x0 + x1 + x2 + x2 * x3 as the nonlinear invariant
# g = sbox_nonlinear_invariants[0] + sbox_nonlinear_invariants[1]
g = x0 + x1 + x2 + x2 * x3
# linear part of nonlinear_invariant g 
l = x0 + x1 + x2

# extend top 64 bits
bool_poly_ring_64 = BooleanPolynomialRing(64, 'x')
xs = bool_poly_ring_64.gens()
# the nonlinear invariant polynomial for Midori64 with the weak key
G = sum(xs[i] + xs[i+1] + xs[i + 2] + xs[i+2] * xs[i + 3] for i in range(0, 64, 4))
L = sum(xs[i] + xs[i+1] + xs[i+2] for i in range(0, 64, 4))
F = sum(xs[i+2] * xs[i + 3] for i in range(0, 64, 4))
# the invariant const: c = L(K1) ⊕ L(α0) ⊕ L(α1) ⊕ · · · ⊕ L(α14).
# -> c = L(K1)

with open("./ct1.bin", "rb") as f:
    data = f.read()
    data = bytearray(data)

# we check that the weak key is used in this challenge by known plaintext-ciphertext pairs
iv = data[0:8]
data = data[8:]
verification = compress(b'P' * 7000)
padding_needed = 8 - (len(verification) % 8)
message = list(verification) + padding_needed * [padding_needed]
assert len(message)  == len(data)
ivs = iv + data[:-8]
assert len(ivs) == len(message)
pt_blocks = [xor(ivs[i:i+8], message[i:i+8]) for i in range(0, len(data), 8)]
ct_blocks = [data[i:i+8] for i in range(0, len(data), 8)]
consts = []
for pt_block,ct_block in zip(pt_blocks, ct_blocks):
    inp_bits64 = [int(b) for b in bin(int.from_bytes(pt_block, 'big'))[2:].zfill(64)][::-1]
    out_bits64 = [int(b) for b in bin(int.from_bytes(ct_block, 'big'))[2:].zfill(64)][::-1]
    invariant_poly_value = G(*inp_bits64) + G(*out_bits64)
    consts.append(invariant_poly_value)
assert len(set(consts)) == 1, f"Invariant polynomial {consts = } is not invariant for all inputs."
print(f"Weak key is used in this challenge with L(K1) = {consts[0]}.")


with open("./ct0.bin", "rb") as f:
    data = f.read()
    data = bytearray(data)
    

# 41 * 7 = 287 unknown bits of the flag
bool_poly_ring_287 = BooleanPolynomialRing(287, 'x')
flag_vars = list(bool_poly_ring_287.gens())

message = compress_to_bits_without_pad(b'PPPMSG:PPPMSG:') 
message += (compress_to_bits_without_pad(b'PCTF{') + flag_vars + compress_to_bits_without_pad(b"}")) * 3000

iv = data[0:8]
data = data[8:]
ct_blocks = [data[i:i+8] for i in range(0, len(data), 8)]
message_blocks = [message[i:i+64] for i in range(0, len(message), 64)]
ivs = iv + data[:-8]
iv_blocks = [ivs[i:i+8] for i in range(0, len(ivs), 8)]
assert len(iv_blocks) == len(message_blocks) == len(ct_blocks)

# checks the weak key property
iv_block0 = iv_blocks[0]
ct_block0 = ct_blocks[0]
message_block0 = compress(b'PPPMSG:PPPMSG:')[:8]
out_bits64 = [int(b) for b in bin(int.from_bytes(ct_block0, 'big'))[2:].zfill(64)][::-1]
inp_bits64 = [int(b) for b in bin(int.from_bytes(xor(message_block0, iv_block0), 'big'))[2:].zfill(64)][::-1]
assert G(*inp_bits64) + G(*out_bits64) == consts[0], f"First block invariant is not satisfied"

# remove the first two blocks since they are known
iv_blocks = iv_blocks[2:]
ct_blocks = ct_blocks[2:]
message_blocks = message_blocks[2:]

# number of blocks we have 
print(f"len(iv_blocks): {len(iv_blocks)}")
print(f"len(ct_blocks): {len(ct_blocks)}")
print(f"len(message_blocks): {len(message_blocks)}")

# the period of plaintext (block by block) is 329
T = 329

message_block_groups = []
ct_block_groups = []
iv_block_groups = []

# we have T groups here, but we don't need too many equations
# so we just pick 16 groups
for idx in range(16):
    mg = [message_blocks[i] for i in range(idx, len(message_blocks), T)]
    cg = [ct_blocks[i] for i in range(idx, len(ct_blocks), T)]
    ig = [iv_blocks[i] for i in range(idx, len(iv_blocks), T)]
    message_block_groups.append(mg)
    ct_block_groups.append(cg)
    iv_block_groups.append(ig)
    # all blocks in the same message_block_group are the same
    assert all(mi == mg[0] for mi in mg), f"Not all blocks in the same group are the same: {idx = }"

polys = []

for iv_blocks, ct_blocks, message_blocks in zip(iv_block_groups, ct_block_groups, message_block_groups):
    base_poly = None
    for iv_block, ct_block, message_block in zip(iv_blocks, ct_blocks, message_blocks):
        out_bits64 = [bool_poly_ring_287(int(b)) for b in bin(int.from_bytes(ct_block, 'big'))[2:].zfill(64)][::-1]
        inp_bits64 = message_block[::-1]
        iv_bits64 = [bool_poly_ring_287(int(b)) for b in bin(int.from_bytes(iv_block, 'big'))[2:].zfill(64)][::-1]
        inp_bits64 = sym_xor(inp_bits64, iv_bits64)
        poly = G(*inp_bits64) + G(*out_bits64) + consts[0]
        if base_poly is None:
            base_poly = poly
        else:
            # if the input unknown message blocks are the same and only the iv differs
            # we can cancel out the quadratic part by combining the two equations 
            linear_poly = base_poly + poly
            # this must be a linear polynomial
            assert linear_poly.degree() == 1, f"Poly degree is not 1: {linear_poly = }"
            polys.append(linear_poly)
            
print(f"Linear eqs: {len(polys)}")
seq = Sequence(polys)
mat, mono = seq.coefficients_monomials()
basis = mat.right_kernel().basis()
print(f"Ker: {len(basis)}")
print(f"Sol: {basis = }")
print(f"{len(mono) = }")
assert len(mono) == len(flag_vars) + 1, f"not all flag variables are included, {-len(mono) + len(flag_vars) + 1} missing"
flagbits = basis[0][:-1]
# print(f"{len(flagbits) = }")
flag_bits = "".join([str(int(b)) for b in flagbits])
flag_bytes = b""
for i in range(0, len(flag_bits), 7):
    flag_bytes +=bytes([int(flag_bits[i:i+7], 2)])
print(f"Flag: {flag_bytes}")