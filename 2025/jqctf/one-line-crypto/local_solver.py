import random
from math import prod

primes_le_103 = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101
]

def server_side_channel_oracle(input_num):
    flag = b"flag{0123qwert45}"
    flag_num = int(flag.hex(), 16)
    pp = input_num ^ flag_num
    for prime in primes_le_103:
        if pp % prime == 0:
            return False
    return True

def crt(remainders, primes):
    x = 0
    product = 1
    for p in primes:
        product *= p
    for a, p in zip(remainders, primes):
        n = product // p
        inv = pow(n, -1, p)
        x += a * inv * n
    return x % product

def sample_mod_r_mod_p(r, p, bit_length = 32, start_bit = 136):
    assert p != 2, "cannot handle the case p=2"
    while True:
        randnum = random.getrandbits(bit_length) << start_bit
        if randnum % p == r:
            yield randnum

def recover_flag(n_sample = 100):
    moduli = {}
    moduli[256] = ord("}")
    for p in primes_le_103[1:]:
        for k in range(p):
            count = 0
            good_k = True
            for input_num in sample_mod_r_mod_p(k, p):
                if not server_side_channel_oracle(input_num):
                    count += 1
                    if count == n_sample:
                        break
                else:
                    good_k = False
                    break
            if good_k:
                print(f"p: {p}, k: {k}, count: {count}")
                moduli[p] = (-k) % p
                break

    primes = [256] + primes_le_103[1:]
    remainders = [moduli[p] for p in primes]
    x = crt(remainders, primes)
    N = int(prod(primes))
    while x < 2**136:
        hex_str = hex(x)[2:]
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        if b"flag" in bytes.fromhex(hex_str):
            return bytes.fromhex(hex_str).decode('utf-8')
        x += N

flag = recover_flag()
print("Recovered Flag:", flag)