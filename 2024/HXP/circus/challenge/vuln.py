#!/usr/bin/env python3

f = 0x1f3267f571be716d65f11ecb21b86d2e9

def to_bits(bs):
    return int.from_bytes(bs)

def from_bits(v):
    return int.to_bytes(v, 16)

def red(x):
    while (l := x.bit_length()) > 128:
        x ^= f << l - 129
    return x

def mul(x, y):
    z = 0
    for i in range(x.bit_length()):
        if (x >> i) & 1:
            z ^= y << i
    return red(z)

def exp(x, n):
    assert n >= 0
    if not n:
        return 1
    if n % 2:
        return mul(x, exp(x, n-1))
    return exp(mul(x, x), n//2)

class Mac:
    def __init__(self, key):
        self.key = key

    def __call__(self, msg):
        tag = exp(to_bits(self.key + bytes([len(msg)]) + msg), 10)
        return from_bits(tag)

if __name__ == '__main__':
    import os, signal
    signal.alarm(60)

    mac = Mac(os.urandom(32))
    for _ in range(99):
        try:
            inp = input().strip().split(' ')
        except EOFError:
            exit()
        cmd, data = inp[0], bytes.fromhex(inp[1])
        if cmd == 'solve':
            break
        if cmd == 'query':
            print(mac(data).hex())
        else:
            print('bad command')
    else:
        print('no more')
        exit()

    key = bytes.fromhex(inp[1])
    mac_ = Mac(key)
    for l in range(256):
        msg = os.urandom(l)
        if Mac(key)(msg) != mac(msg):
            print('wrong key')
            break
    else:
        print(open('flag.txt').read().strip())

