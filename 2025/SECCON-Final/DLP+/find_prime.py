from Crypto.Util.number import isPrime
from sage.all import factor, GF
import requests
import json
import time

def query_factor(k, a):
    factors = requests.get(f"https://factordb.com/api?query={2**k + a}").json()
    time.sleep(0.3)
    try:
        return factors["factors"]
    except:
        time.sleep(1)
        factors = requests.get(f"https://factordb.com/api?query{2**k + a}").json()
        return factors["factors"]
    
def factordb(n):
    factors = requests.get(f"https://factordb.com/api?query={n}").json()
    time.sleep(0.3)
    try:
        return factors["factors"]
    except:
        time.sleep(1)
        factors = requests.get(f"https://factordb.com/api?query{n}").json()
        return factors["factors"]    


smoothness_B = 2**60

# 1125
for k in range(1000, 2400):
    factors = query_factor(k, 3 * (-1)**(k % 2))
    for numstr, e in factors:
        num = int(numstr)
        if not isPrime(num):
            continue
        if num.bit_length() > 512:
            facts = factordb(num - 1)
            smooth_order = 1
            for fact, ei in facts:
                if int(fact) < smoothness_B:
                    smooth_order *= int(fact) ** int(ei)
            print(f"{k = }, {num = }")
            print(f"{smooth_order = } {smooth_order.bit_length() = }")
            if smooth_order.bit_length() > 512:
                exit()