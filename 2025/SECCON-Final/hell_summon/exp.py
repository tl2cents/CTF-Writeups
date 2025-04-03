from sage.all import matrix, ZZ, lcm, gcd
from random import randint
from Crypto.Util.number import getPrime
from pwn import remote, process
from sage.all import PolynomialRing, GF, Zmod, ZZ, matrix, QQ
from ast import literal_eval
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor
local = True
chunk_size = 5

if local:
    io = process(['python3', 'server.py'])
else:
    # hell-summon.int.seccon.games 8888
    io = remote('hell-summon.int.seccon.games', 8888)

def encrypt(message,priv):
    p,r,H = priv
    assert len(message) % 5 == 0

    message_chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

    ciphertext = b""
    mac = 0
    for chunk in message_chunks:
        temp = strxor(chunk, H)
        mac = (r*(mac + bytes_to_long(temp))) % p
        ciphertext += temp

    return ciphertext, long_to_bytes(mac)

def decrypt(ciphertext, mac, priv):
    mac = bytes_to_long(mac)
    p,r,H = priv
    ciphertext_chunks = [ciphertext[i:i + chunk_size] for i in range(0, len(ciphertext), chunk_size)]

    message = b""
    expected_mac = 0
    for chunk in ciphertext_chunks:
        expected_mac = (r*(expected_mac + bytes_to_long(chunk))) % p
        message += strxor(chunk, H)
    if mac == expected_mac:
        return message
    else:
        return None

def initialize(io:remote):
    io.recvuntil(b"p=")
    p = int(io.recvline().strip().decode())
    io.recvuntil(b"messages=")
    ms = literal_eval(io.recvline().strip().decode())
    io.recvuntil(b"truncated_macs=")
    ts = literal_eval(io.recvline().strip().decode())
    return p, ms, ts

def hnp_sum_solver(a, q, E, T):
    """
    Solves the HNP-SUM problem for a given lattice leaks a, modulus q, error bound E, and target bound T.
    hnp sum sample :    a_i + e_i = t_i * x \mod q 
    where x is the secret, e_i <= E, t_i <= T, and x is the fixed secret.

    Args:
        a (list[ZZ]): The leaks information of HNP-SUM problem.
        q (ZZ): The modulus of the HNP-SUM problem. 
        E (ZZ): The error bound of the HNP-SUM problem. 
        T (ZZ): The target bound of the HNP-SUM problem.

    Returns:
        list[ZZ]: The solution of the HNP-SUM problem : [t_1, t_2, ..., t_n]
    """
    n = len(a)
    M = matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i,n] = a[i]
        M[i, i] = 2*E
    M[n, n] = q
    B = M.LLL()
    
    new_E = max(E, T)
    sub_lattice = B[:(n-1),:n] / (2*E) * (2*new_E)
    sub_lattice[:, 0] /= (2 * new_E)
    t0 = None
    t0s = []
    ts = []
    for i in range(1, n):
        sub_lattice[:,i] /= (2 * new_E)
        sub_lattice = sub_lattice.LLL()
        ti, t0_alt = sub_lattice[0,0], -sub_lattice[0,i]
        if t0_alt < 0:
            t0_alt, ti = -t0_alt, -ti
        t0s.append(t0_alt)
        ts.append(ti)
        sub_lattice[:,i] *= (2 * new_E)
    t0 = lcm(t0s)
    assert t0 < T
    rts = [ZZ(t0)]
    for ti, _t0 in zip(ts, t0s):
        rts.append(ZZ(ti * (t0 // _t0)))
    return rts         

p, ms, ts = initialize(io)
ms = [bytes_to_long(bytes.fromhex(m)) for m in ms]
# ts = [bytes_to_long(bytes.fromhex(t)) for t in ts]
ts = [bytes_to_long(bytes.fromhex(t) + b"\x00\x00") for t in ts]
p = ZZ(p)
T = 2**40
E = 2**16
mhs = hnp_sum_solver(ts, p, E, T)
print(mhs)
mhs_bits = [mh.nbits() for mh in mhs]
H = mhs[0] ^ ms[0]
assert H == mhs[1] ^ ms[1], "H is not same"
print(f"{H = }")
n = len(ms)
M = matrix(QQ, n + 2, n + 2)
for i in range(n):
    M[0, i] = mhs[i]
    M[1, i] = -ts[i]
    M[i + 2, i] = p
M[0, n] = ZZ(E) / ZZ(p)
M[1, n + 1] = ZZ(1) / p
M = M.LLL()
for row in M:
    if row[:n] == 0:
        continue
    if all([ZZ(r) < E for r in row[:n]]):
        row_nbits = [ZZ(r).nbits() for r in row[:n]]
        print(row_nbits)
        sym = row[n+1] * p
        assert sym == 1 or sym == -1
        r = row[n]/(ZZ(E)/ZZ(p)) * sym % p
        print(f"{r = }")
        break

msg = b"Kurenaif,gimme flag!"
c, mac = encrypt(msg, (p, r, long_to_bytes(H)))
priv = (p, r, long_to_bytes(H, 5))
assert decrypt(c, mac, priv) == msg
io.sendlineafter(b"ciphertext:", c.hex().encode())
io.sendlineafter(b"mac:", mac.hex().encode())
io.interactive()
