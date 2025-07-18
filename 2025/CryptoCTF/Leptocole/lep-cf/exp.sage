from pwn import remote
from re import findall  
# from sage.all import *

q = 127
k,n = 26,14
io = remote("91.107.133.165", "37373")
io.recvuntil(b'uit\n')
io.sendline(b'g')
io.recvuntil(b'G = ')
Glist = io.recvuntil(b'\nH')[:-2].decode()

io.recvuntil(b'= ')
Hlist = io.recvuntil('\n┃'.encode())[:-4].decode()  
def parse_matrix(s):
    rows = s.split('\n')
    matrix = []
    for row in rows:
        if row.strip():
            matrix.append([int(x) for x in findall(r'\d+', row)])
    return matrix

F = GF(q)
G = matrix(F, parse_matrix(Glist))
H = matrix(F, parse_matrix(Hlist)) 

load("utils.sage")
load("lep_solver.sage")

q = 127
n = 26
k = 14

Fq = GF(q)

# G1 = random_matrix(Fq, k, n)
# Q = randomMonomial(n, q)
# G2 = (G1*Q).echelon_form()

result = lepCollSearch(G, H)
if result != None:
    U, P = result
    # assert G2 == U*G1*P
    assert H == U*G*P
    print("lepCollSearch succesfully recovered solution.")


_U,_P = result
print(_U*G*_P==H) 
print(_U.dimensions())
print(_P.dimensions())
io.recvuntil(b"uit\n")
io.sendline(b"s")
io.recvuntil(b"Please send the matrix U row by row: ")
print(_U.dimensions())
print(_P)
for i in range(14):
    print(str(list(_U[i]))[1:-1])
    io.sendline(str(list(_U[i]))[1:-1].encode())
io.recvuntil(b"Now, please send the matrix P row by row: ")
for _ in range(n):
    print(str(list(_P[_]))[1:-1])
    io.sendline(str(list(_P[_]))[1:-1].encode())
# io.interactive()
print(io.recvline().decode())