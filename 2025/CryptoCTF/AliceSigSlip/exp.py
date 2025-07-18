from pwn import * 
from Crypto.Util.number import *
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512, SHAKE256
from Crypto.PublicKey.ECC import (EccKey,
                                  construct,
                                  _import_ed25519_public_key,
                                  _import_ed448_public_key)

from Crypto.Math.Numbers import Integer
_order = 7237005577332262213973186563042994240857116359379907606001950938285454250989

def get_data(io):
    io.recvuntil(b"uit\n")
    io.sendline(b"g")
    datas = [[None,None,None,None] for i in range(4)]
    io.recvuntil(b"0 : ")
    datas[0][0] = bytes.fromhex(io.recvuntil(b',')[:-1].decode())
    datas[0][1] = bytes.fromhex(io.recvuntil(b',')[:-1].decode())
    datas[0][2] = bytes.fromhex(io.recvuntil(b',')[:-1].decode())
    datas[0][3] = bytes.fromhex(io.recvuntil(b'\n')[:-1].decode())
    io.recvuntil(b"1 : , ") 
    datas[1][1] = bytes.fromhex(io.recvuntil(b',')[:-1].decode())
    datas[1][2] = bytes.fromhex(io.recvuntil(b',')[:-1].decode())
    datas[1][3] = bytes.fromhex(io.recvuntil(b'\n')[:-1].decode())
    io.recvuntil(b"2 : , , ")  
    datas[2][2] = bytes.fromhex(io.recvuntil(b',')[:-1].decode())
    datas[2][3] = bytes.fromhex(io.recvuntil(b'\n')[:-1].decode())
    io.recvuntil(b"3 : , , , ")   
    datas[3][3] = bytes.fromhex(io.recvuntil(b'\n')[:-1].decode())
    return datas

# context.log_level = 'debug'
# nc 91.107.133.165 13777
# io = process(["python3", 'AliceSigSlip.py'])
io = remote("91.107.133.165", 13777)
datas = get_data(io)
pk = datas[0][0]
public_key = eddsa.import_public_key(encoded=pk)
_A = public_key._export_eddsa_public()
m1 = datas[0][3] 
R1,s1 = datas[0][1],datas[0][2] 
k_hash1 = SHA512.new(R1 + _A + m1).digest()
k1 = Integer.from_bytes(k_hash1, 'little') % _order

# update idx 1
m2 = datas[1][3]
R2,s2 = datas[1][1],datas[1][2]
k_hash2 = SHA512.new(R2 + _A + m2).digest()
k2 = Integer.from_bytes(k_hash2, 'little') % _order
io.recvuntil(b"uit\n")
io.sendline(b"u")
io.recvuntil(b"row_inx, public_key, r, s, msg:")
io.sendline(f"1,{pk.hex()},{R2.hex()},{s2.hex()},{m2.hex()}".encode())

# s * k = h + r * d
# io.interactive()
# update idx 2
msg3 = b"No flag for those who give up too soon, says Alice."
d = 13456
order_8_Q_y = 55188659117513257062467267217118295137698188065244968500265048394206261417927
pk = bytearray(int(order_8_Q_y).to_bytes(32, 'little'))
public_key = eddsa.import_public_key(encoded=pk)
Q = 8 * public_key.pointQ
assert Q.x == 0 and Q.y == 1, "The public key does not correspond to a point of order 8."
m3 = datas[2][3]
assert m3 == msg3, "The message does not match the expected value."
R3, S3 = datas[2][1], datas[2][2]
s3 = Integer.from_bytes(S3, 'little') 
print(f"target {R3 = }")
print(f"target {s3 = }")

point1 = (s3 * 8) * public_key._curve.G
print(f"target {point1.xy = }")
point_R = pow(8, -1, _order) * point1
print(f"target {point_R.xy = }")
R3 = EccKey(point=point_R)._export_eddsa_public()
alice_data = (2, public_key._export_eddsa_public(), R3, S3, m3)
io.recvuntil(b"uit\n")
io.sendline(b"u")
io.recvuntil(b"row_inx, public_key, r, s, msg:")
io.sendline(f"{alice_data[0]},{alice_data[1].hex()},{alice_data[2].hex()},{alice_data[3].hex()},{alice_data[4].hex()}".encode())



# update idx 3
alice_key = ECC.generate(curve = "ed25519")
apk = alice_key.public_key().export_key(format="raw")
signer = eddsa.new(alice_key, "rfc8032")
m4 = b"Alice never gives up; that's why she always gets the flag."
signs = signer.sign(m4)
alice_data = (3, apk, signs[:32], signs[32:], m4)
io.recvuntil(b"uit\n")
io.sendline(b"u")
io.recvuntil(b"row_inx, public_key, r, s, msg:")
io.sendline(f"{alice_data[0]},{alice_data[1].hex()},{alice_data[2].hex()},{alice_data[3].hex()},{alice_data[4].hex()}".encode())

# update idx 4
m4 = b"Alice loves solving ciphers, especially when they're tricky."
signs =signer.sign(m4)
alice_data = (4, apk, signs[:32], signs[32:], m4)
io.recvuntil(b"uit\n")
io.sendline(b"u")
io.recvuntil(b"row_inx, public_key, r, s, msg:")
io.sendline(f"{alice_data[0]},{alice_data[1].hex()},{alice_data[2].hex()},{alice_data[3].hex()},{alice_data[4].hex()}".encode())

# ===========
io.recvuntil(b"uit\n")
io.sendline(b"a")
io.interactive()