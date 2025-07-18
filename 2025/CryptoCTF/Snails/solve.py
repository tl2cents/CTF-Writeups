from sage.all import EllipticCurve, GF, matrix, vector, ZZ
from Crypto.Util.number import bytes_to_long, getRandomNBitInteger, long_to_bytes
from hashlib import sha512
import os
from pwn import remote, process, log
import string
import random
from tqdm import tqdm


table = string.ascii_letters + string.digits


def gen_small_msg(ub = 2**(512 - 8), contain = '✔✔✔ My signature is the priority'.encode()):
    for ch1 in range(33, 128):
        for ch2 in range(33, 128):
            msg = contain + bytes([ch1, ch2])
            h = bytes_to_long(sha512(msg).digest())
            if h < ub:
                yield msg
            msg = bytes([ch1, ch2]) + contain
            h = bytes_to_long(sha512(msg).digest())
            if h < ub:
                yield msg
            msg = bytes([ch1]) + contain + bytes([ch2])
            h = bytes_to_long(sha512(msg).digest())
            if h < ub:
                yield msg
# k * s = h + r * d
# k = s_inv * h + (r * d) * s_inv

p = 0x013835f64744f5f06c88c8d7ebfb55e127d790e5a7a58b7172f033db4afad4aca1ae1cdb891338cf963b30ff08d6af71327770d00c472c52290a60fb43f1d070025b
a = 0x0109ec0177a5a57e7b7890993e11ba1bc7ba63c1f2afd904a1df35d1fda7363ea8e83f3291e25b69dac26d046dc5ba9a42ff74cd7e52c9df5dbe8d4d02755d26b111
b = 0x0037c84047a6cc14e36d180f9b688fe9959cb63f4ac37b22eb24559e83cfc658ff0ab753540b8ab8d85a62dd67aa92f79dec20d28e453d4663ef2882c7b031ddc0b9
n = 0x013835f64744f5f06c88c8d7ebfb55e127d790e5a7a58b7172f033db4afad4aca1aad8763fe2401b5189d1c449547a6b5295586ce30c94852845d468d52445548739
x = 0x00339495fdbeba9a9f695d6e93effeb937609ce2e628958cd59ba307eb3a43c4c3a54b9b951cd593c876df93a9b0ed7d64df641af94668cb594b6a636ae386e1ac1b
y = 0x00038389f29ad8c87e79a8b854e78310b72febb6b1840e360b0a43733933529ee6a04f6d7ea0d91104eb83d1162d55c410eca1c7b45829925fb2a9bf9c1232c32972
E = EllipticCurve(GF(p), [a, b])
G = E(x, y)

local = False
# nc 91.107.133.165 33337
io = remote("91.107.133.165", 33337) if not local else process(["sage", "snails.sage"])

def sign(msg: str, io: remote = io):
    io.sendlineafter(b"[Q]uit\n", b"s")
    io.sendlineafter(b"Please send your message: ", msg)
    io.recvuntil(b"r = ")
    r = int(io.recvline().strip())
    io.recvuntil(b"s = ")
    s = int(io.recvline().strip())
    return (r, s)

msgs = [b'$\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityN', b'(w\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b')\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority;', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority*T', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority*w', b'+*\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority-4', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority-T', b'.s\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority07', b'0\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityI', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority0\x7f', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority2z', b"\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority3'", b'31\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'3\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityW', b'48\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'7\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityF', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority;Q', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority<A', b'<K\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'<\\\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority=0', b'=v\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority>Y', b'?N\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority?\x7f', b'@\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority1', b'A;\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'C\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityO', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityCc', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityEe', b'E\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityg', b'H/\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'H;\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityHg', b'I\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityX', b'JP\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'L\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority9', b'L\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityI', b'L\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityR', b'M{\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'N\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityr', b'O\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityy', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityQ{', b'Q~\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'R!\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'S3\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityTr', b'UV\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'W\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityl', b'X\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityF', b'Y\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority8', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityYO', b'[X\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority[m', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority\\m', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority]5', b']\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority;', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority_E', b'_^\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'b>\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'br\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'c~\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'eH\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the prioritye\x7f', b'fJ\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'j\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority-', b'k\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityi', b'l\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority(', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the prioritymS', b'm\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityk', b'n\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority3', b'n~\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'p+\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'p\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityn', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityq/', b'rQ\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'u+\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'u\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority9', b'uF\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityuV', b'uu\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityvH', b'w$\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the prioritywk', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityx-', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityxq', b'\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityyY', b'z6\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'z{\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'{.\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'~Q\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'~\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityg', b'\x7f#\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\x7fU\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priority', b'\x7f\xe2\x9c\x94\xe2\x9c\x94\xe2\x9c\x94 My signature is the priorityZ']

hmsgs = [bytes_to_long(sha512(msg).digest()) for msg in msgs]
assert all(h < 2**(512 - 8) for h in hmsgs), "Some hashes are too large!"
# msgs = list(gen_small_msg())
print(f"Found {len(msgs)} small messages")
# print(f"{msgs = }")

n_sample = len(hmsgs)
sigs = []
for msg in tqdm(msgs):
    r, s = sign(msg)
    sigs.append((r, s))

# k * s = h + r * d
# k = s_inv * h + (r * d) * s_inv

hnp_data = [(pow(s, -1, n) * h, pow(s, -1, n) * r)  for (r, s), h in zip(sigs, hmsgs)]
mat = matrix(ZZ, n_sample + 2, n_sample)
for i in range(n_sample):
    mat[0, i] = hnp_data[i][0]
    mat[1, i] = hnp_data[i][1]
    mat[2 + i, i] = n

L = mat.LLL()
for row in L:
    row_nbits = [int(num).bit_length() for num in row]
    if all(nbits <= 512 - 8 for nbits in row_nbits):
        log.info(f"{row_nbits = }")
        # log.info(f"{row = }")
        d = (abs(row[0]) * sigs[0][1] - hmsgs[0]) * pow(sigs[0][0], -1, n) % n
        print(f"Found {long_to_bytes(d)}")