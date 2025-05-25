from pwn import remote, process, context
import time
import os
from sage.all import crt, prod
import random
from Crypto.Util.number import long_to_bytes
# context.log_level = "debug"

local = True
if local:
    io = process(["sage", "server.sage"], env={"HOME": os.environ["HOME"], "FLAG": "flag{0123qwert45}"}, stderr=process.STDOUT)
else:
    io = remote("39.106.16.204", 24045)

primes_le_103 = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101
]

def server_side_channel_oracle(input_num, n_estimate = 100, time_threshold = 0.5):
    st = time.time()
    io.sendlines([str(input_num).encode()] * n_estimate)
    io.recvuntil("🌌 ".encode() * n_estimate)
    et = time.time()
    cost = et - st
    return cost > time_threshold

def sample_mod_r_mod_p(r, p, bit_length = 32, start_bit = 17 * 8):
    assert p != 2, "cannot handle the case p=2"
    while True:
        randnum = random.getrandbits(bit_length) << start_bit
        if randnum % p == r:
            yield randnum

def recover_flag(primes, n_sample = 100):
    moduli = {}
    for p in primes:
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
                print(f"p: {p}, k: {k}, r: {(-k) % p}")
                moduli[p] = (-k) % p
                break
        assert good_k, f"Failed to find k for prime {p}"
    remainders = [moduli[p] for p in primes]
    x = int(crt(remainders, primes))
    return x, int(prod(primes))

flag_res, mod = recover_flag(primes_le_103[1:], n_sample=100)
while flag_res < 2**136:
    flag = long_to_bytes(flag_res)
    if flag.startswith(b"flag{"):
        print(f"{flag = }")
        break
    flag_res += mod