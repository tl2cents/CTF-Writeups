import os, random
flag = os.getenv("FLAG", "flag{redacted}")

def encrypt(key, message):
    otp = random.Random(key).randbytes(len(message))
    return bytes([i ^ j for i, j in zip(otp, message)])

while True:
    key = int.from_bytes(flag.encode(), 'big')
    msg = bytes.fromhex(input('💬'))[:64]
    err = int(input('🔧'))
    print('🔒', encrypt(key ^ err, msg).hex())
