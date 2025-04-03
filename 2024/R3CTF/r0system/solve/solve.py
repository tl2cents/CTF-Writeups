from user import Users
from utils import ECDH, b2p, p2b
from random import randint
from hashlib import md5
from Crypto.Cipher import AES

def pad(msg):
    return msg + bytes([i for i in range(16 - int(len(msg) % 16))])

def enc(msg,key):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(pad(msg))

def dec(msg,key):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.decrypt(msg)

ska = int(0xd0c27e65e1bbe24a794c78a40ae0b45209e7bc3f0cb8f49b79ab31797b591dce)
pka = bytes.fromhex("8f1d7fd6b5b476f19460afa75104e819bd09780015c04fe61ef503c6ef771ccca279eeee164e992c5504ab496e532cf013170cebf4c55ea78b4cf9f2d55859bd")
pkb = bytes.fromhex("f7a7f4a2ff6cc727571258985385f202a8248997973a1b08ac7adb78dd73755c93edd64d8b9c03cf05494da92af46fa3983ed3f1d8c64c02827f22fd57242713")
pka = b2p(pka)
pkb = b2p(pkb)
enc_flag = bytes.fromhex("fed3a1657c7c8cc0bf014cd6f54ac24164cdd136d02f642fe4653f36321ba586460019baa401bb633cee8f444d375e28a72ff3ad1f463c29d7a02ba02e675fd2140e82877f8f481c44da50415b61c4524283539265845f61085c6a93802ca07b")


ecdh_alice = ECDH()
ecdh_alice.private_key = ska
ecdh_alice.public_key = pka

ecdh_bob = ECDH()
ecdh_bob.public_key = pkb

shared_secret = ecdh_alice.exchange_key(ecdh_bob.public_key)
print(shared_secret)

flag = dec(enc_flag, shared_secret)
print(flag)
