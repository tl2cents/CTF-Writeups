#!/usr/bin/env sage
proof.all(False)

bits = 1024
errs = 16

p = random_prime(2^(bits//2))
q = random_prime(2^(bits//2))
n = p * q
e = 0x10001
print(f'{n = :#x}')
print(f'{e = :#x}')

flag = pow(int.from_bytes(open('flag.txt','rb').read().strip()), e, n)
print(f'{flag = :#x}')

d = inverse_mod(e, lcm(p-1, q-1))
locs = sorted(Subsets(range(bits), errs).random_element())
for loc in locs:
    d ^^= 1 << loc
print(f'{d = :#x}')

