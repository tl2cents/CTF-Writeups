from pwn import remote, context, log, process
import os
from recover_x import recover_sk
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import GF, PolynomialRing
from utils import ECDH, b2p, p2b
from Crypto.Cipher import AES

def pad(msg):
    return msg + bytes([i for i in range(16 - int(len(msg) % 16))])

def enc(msg,key):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(pad(msg))

def dec(msg,key):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.decrypt(msg)

def sing_up(io:remote, uname:bytes, pwd:bytes):
    io.sendlineafter(b"Now input your option: ", b'3')
    io.sendlineafter(b"Username[HEX]: ", uname.hex().encode())
    io.sendlineafter(b"Password[HEX]: ", pwd.hex().encode())
    io.recvuntil(b"token is ")
    token = io.recvline().strip().decode()
    return token  

def login_by_password(io:remote, uname:bytes, pwd:bytes):
    io.sendlineafter(b"Now input your option: ", b'1')
    io.sendlineafter(b"Username[HEX]: ", uname.hex().encode())
    io.sendlineafter(b"Password[HEX]: ", pwd.hex().encode())
    respone = io.recvline().strip().decode()
    if respone == "Login successfully!":
        return True, uname
    return False, uname

def login_by_token(io:remote, uname:bytes, token:bytes):
    io.sendlineafter(b"Now input your option: ", b'2')
    io.sendlineafter(b"Username[HEX]: ", uname.hex().encode())
    io.sendlineafter(b"Token[HEX]: ", token.hex().encode())
    respone = io.recvline().strip().decode()
    if respone == "Login successfully!":
        return True, uname
    return False, uname

def reset_password(io:remote, uname:bytes, new_pwd:bytes):
    io.sendlineafter(b",do you need any services? ", b'1')
    io.sendlineafter(b"Username[HEX]: ", uname.hex().encode())
    io.sendlineafter(b"New Password[HEX]: ", new_pwd.hex().encode())
    respone = io.recvline().strip().decode()
    return respone

def exit_login(io:remote):
    io.sendlineafter(b",do you need any services? ", b'5')

def get_PublicChannels(io:remote):
    io.sendlineafter(b"do you need any services? ", b'3')
    # respone = io.recvuntil(b" Wow! I know your flag now! ")
    io.recvuntil(b"[AliceIsSomeBody] to [BobCanBeAnyBody]: My Pubclic key is: ")
    pka = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b"[BobCanBeAnyBody] to [AliceIsSomeBody]: My Pubclic key is: ")
    pkb = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b"BobCanBeAnyBody]: Now its my encrypted flag:\n[AliceIsSomeBody] to [BobCanBeAnyBody]: ")
    encflag = bytes.fromhex(io.recvline().strip().decode())
    return pka, pkb, encflag

def get_ecdh_keys(io:remote):
    io.sendlineafter(b",do you need any services? ", b'4')
    io.recvuntil(b"Your private key is:")
    sk = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b"Your public key is:")
    pk = bytes.fromhex(io.recvline().strip().decode())
    return sk, pk

def gen_possible_tokens(sk, us, ys, uname, degree, mod):
    # x = yi(ui + ki) % mod
    R = GF(mod)
    pr = PolynomialRing(R, names=('x',))
    next_u = bytes_to_long(uname)
    tokens = []
    for x in sk:
        ks = []
        for ui, yi in zip(us, ys):
            ki = x * pow(yi, -1, mod) - ui
            ki = int(ki) % mod
            ks.append(ki)
        points = [(ks[i], ks[i+1]) for i in range(len(ks) - 1)]
        poly = pr.lagrange_polynomial(points)
        if poly.degree() == degree:
            next_k = poly(ks[-1])
            token_num = int((x * pow(next_k + next_u, -1, mod)) % mod)
            tokens.append(long_to_bytes(token_num).hex())
    return tokens
        

local = False
# ctf2024-entry.r3kapig.com:30517
io = process(['python3', 'server.py']) if local else remote('ctf2024-entry.r3kapig.com', 30517)


# context.log_level = 'debug'

# recover sk
us = []
tokens = []
pwds = []
unames = []
N = 10

for i in range(N):
    uname = b'tl2cents' + str(i).encode()
    pwd = b'password_' + os.urandom(8).hex().encode()
    token = sing_up(io, uname, pwd)
    pwds.append(pwd)
    unames.append(uname)
    # log.info(f"{uname}'s token: {token}")
    tokens.append(int(token.strip("."), 16))
    us.append(bytes_to_long(uname))
    
degree = 7
MOD  = 0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000283
sk = recover_sk(us, tokens, degree, MOD)
BobUsername   = b'BobCanBeAnyBody'
bob_tokens = gen_possible_tokens(sk, us, tokens, BobUsername, degree, MOD)
log.info(f"Bob's possible tokens number : {len(bob_tokens)}")

is_login, uname = login_by_password(io, unames[-1], pwds[-1])
assert is_login, "Login failed"
pka, pkb, encflag = get_PublicChannels(io)
log.info(f"pka: {pka.hex()}")
log.info(f"pkb: {pkb.hex()}")
log.info(f"encflag: {encflag.hex()}")

exit_login(io)
# try login by token
is_login = False
for token in bob_tokens:
    is_login, uname = login_by_token(io, BobUsername, bytes.fromhex(token))
    if is_login:
        log.info(f"Login successfully with token: {token}")
        break
if not is_login:
    log.error("Login failed")
    exit()
sk, pk = get_ecdh_keys(io)
assert pk == pkb, "ECDH keys not match"

pka = b2p(pka)
pkb = b2p(pkb)
ecdh_alice = ECDH()
ecdh_alice.private_key = bytes_to_long(sk)
ecdh_alice.public_key = pkb

ecdh_bob = ECDH()
ecdh_bob.public_key = pka

shared_secret = ecdh_alice.exchange_key(ecdh_bob.public_key)
log.info(shared_secret.hex())

flag = dec(encflag, shared_secret)
log.info(f"flag : {flag}")