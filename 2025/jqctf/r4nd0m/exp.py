from pwn import remote
from Crypto.Util.number import long_to_bytes

def get_key_stream(io: remote, errs: list[int]):
    msg = b"\x00" * 64
    outs = []
    for err in errs:
        io.sendlineafter('💬'.encode(), msg.hex().encode())
        io.sendlineafter('🔧'.encode(), str(err).encode())
        io.recvuntil('🔒'.encode())
        enc = io.recvline().strip()
        outs.append(bytes.fromhex(enc.decode()))
    return outs
        
# -(x^-y) = -(x^(~y + 1))
# ~(x^(~y + 1)) + 1
ip = '39.106.16.204'
port = 44623
io = remote(ip, port)

flag_bit = ""
recovered = 0
for i in range(128 * 8):
    y1 = recovered + (1 << i)
    y2 = recovered - (1 << i)
    inp_pair = [y1, y2]
    out1, out2 = get_key_stream(io, inp_pair)
    if out1 != out2:
        recovered += (1 << i)
    print(f"{long_to_bytes(recovered) = }")
    if b"flag{" in long_to_bytes(recovered):
        print(f"found flag: {long_to_bytes(recovered)}")
        break