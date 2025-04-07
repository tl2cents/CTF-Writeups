from pwn import remote

# nc innov8-enerv8.chal.pwni.ng 1337

io = remote("innov8-enerv8.chal.pwni.ng", 1337)
s0 = 17263521175733561678
s1 = 1049317583000366139
N = 2**52 - 1

io.sendlineafter(b"part 1: ", b"oaq1MD92evRsDZvH")
io.sendlineafter(b"s0: ", str(s0).encode())
io.sendlineafter(b"s1: ", str(s1).encode())
io.sendlineafter(b"maximum: ", str(N).encode())
io.interactive()
