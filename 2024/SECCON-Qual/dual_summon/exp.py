from pwn import remote, process, info
from sage.all import GF


x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)


# Converts an integer to a gf2e element, little endian.
def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])

# Converts a gf2e element to an integer, little endian.
def _from_gf2e(p):
    n = p.integer_representation()
    ans = 0
    for i in range(128):
        ans <<= 1
        ans |= ((n >> i) & 1)
    return int(ans)

# nc dual-summon.seccon.games 2222
local = False
if local:
    io = process(['python3', 'server.py'])
else:
    io = remote('dual-summon.seccon.games', 2222)

pt1 = b"\x00"*16
pt2 = b"\x00"*15 + b"\x01"
p1 = _to_gf2e(int.from_bytes(pt1, 'big'))
p2 = _to_gf2e(int.from_bytes(pt2, 'big'))
# gcm length block
l = _to_gf2e(((8 * 0) << 64) | (8 * 16))

def summon_oracle(io: remote, number:int, name:bytes):
    io.sendlineafter(b"[1] summon, [2] dual summon >", b'1')
    io.sendlineafter('>', str(number).encode())
    io.sendlineafter('>', name.hex().encode())
    io.recvuntil(b'tag(hex) = ')
    tag = io.recvline().strip().decode()
    return bytes.fromhex(tag)

def leak_H_key(io: remote, number: int = 1):
    # leak H_key
    tag1 = summon_oracle(io, number, pt1)
    tag2 = summon_oracle(io, number, pt2)
    t1 = _to_gf2e(int.from_bytes(tag1, 'big'))
    t2 = _to_gf2e(int.from_bytes(tag2, 'big'))
    h_square = (t1 - t2) / (p1 - p2)
    h = h_square.sqrt()
    return h, t1, t2

# h1^2 p + h1 * l + c1 = h2^2 p + h2 * l + c2
h1, t11, t12 = leak_H_key(io, 1)
h2, t21, t22 = leak_H_key(io, 2)
# delta = t11 - t21
# = h1 * l + c1  - h2 * l - c2  + h1^2 p - h2^2 p
delta = t21 - t11
# (h1^2 - h2^2) delta_p = -delta
delta_p = -delta / (h1 ** 2 - h2 ** 2)
target_pt = _from_gf2e(delta_p).to_bytes(16, 'big')

io.sendlineafter(b"[1] summon, [2] dual summon >", b'2')
io.sendlineafter('>', target_pt.hex().encode())
io.interactive()