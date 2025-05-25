from pwn import remote, process, context
import time
import os
import random
import sys

# context.log_level = "debug"

local = False
if local:
    io = process(["sage", "server.sage"], env={"HOME": os.environ["HOME"], "FLAG": "flag{0123qwert45}"}, stderr=process.STDOUT)
else:
    # 39.106.16.204:24045
    io = remote("39.106.16.204", 24045)

# 50 0.2
# 100 0.5
# 50 0.3
def server_side_channel_oracle(input_num, n_estimate = 50, time_threshold = 0.3):
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

def recover_mod_p(p, n_sample = 100):
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
            break
    assert good_k, f"Failed to find k for prime {p}"
    return (-k) % p


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python exp.py <ps> <n_sample>")
        sys.exit(1)
    ps = eval(sys.argv[1])  # e.g., [73,79,83,89,97,101]
    n_sample = int(sys.argv[2])
    moduli = {}
    for p in ps:
        r = recover_mod_p(p, n_sample)    
        print(f"Recovered x = {r} mod {p}")
    io.close()