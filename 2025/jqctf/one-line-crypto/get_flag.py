from sage.all import crt, prod
from Crypto.Util.number import long_to_bytes
primes_le_103 = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101
]

primes = [256] + primes_le_103[1:]
moduli = {}
moduli[256] = ord("}")
moduli[3] = 2
moduli[5] = 1
moduli[7] = 0 # [0, 1]
moduli[11] = 7
moduli[13] = 1

moduli[17] = 4
moduli[19] = 9
moduli[23] = 16
moduli[29] = 24

moduli[31] = 7
moduli[37] = 22
moduli[41] = 27
moduli[43] = 6

moduli[47] = 39
moduli[53] = 16
moduli[59] = 40
moduli[61] = 13

moduli[67] = 36
moduli[71] = 8
moduli[73] = 48
moduli[79] = 29

moduli[83] = 66
moduli[89] = 78
moduli[97] = 53
moduli[101] = 65

primes = list(moduli.keys())
remainders = [moduli[p] for p in primes]
# remainders = [moduli[p] for p in primes]
flag_res = int(crt(remainders, primes))
mod = int(prod(primes))
while flag_res < 2**136:
    flag = long_to_bytes(flag_res)
    # print(f"{flag = }")
    if flag.startswith(b"flag{"):
        print(f"{flag = }")
        break
    flag_res += mod