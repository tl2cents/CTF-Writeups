from pwn import remote, context, log
import os


def sing_up(io:remote, uname:bytes, pwd:bytes):
    io.sendlineafter(b"Now input your option: ", b'3')
    io.sendlineafter(b"Username[HEX]: ", uname.hex())
    io.sendlineafter(b"Password[HEX]: ", pwd.hex())
    io.recvuntil(b"token is ")
    token = io.recvline().strip().decode()
    return token  

def login_by_password(io:remote, uname:bytes, pwd:bytes):
    io.sendlineafter(b"Now input your option: ", b'1')
    io.sendlineafter(b"Username[HEX]: ", uname.hex())
    io.sendlineafter(b"Password[HEX]: ", pwd.hex())
    respone = io.recvline().strip().decode()
    if respone == "Login successfully!":
        return True, uname
    return False, uname

def reset_password(io:remote, uname:bytes, new_pwd:bytes):
    io.sendlineafter(b"Hello ", uname + b",do you need any services? ", b'1')
    io.sendlineafter(b"Username[HEX]: ", uname.hex())
    io.sendlineafter(b"New Password[HEX]: ", new_pwd.hex())
    respone = io.recvline().strip().decode()
    return respone

# ctf2024-entry.r3kapig.com:31569
io = remote('ctf2024-entry.r3kapig.com', 31569)

context.log_level = 'debug'

uname = b'tl2cents'
pwd = b'password_' + os.urandom(8).hex().encode()
token = sing_up(io, uname, pwd)
log.info(f"{uname}'s token: {token}")

log_in, uname = login_by_password(io, uname, pwd)
if log_in:
    log.info(f"{uname} login successfully!")
else:
    log.info(f"{uname} login failed!")
