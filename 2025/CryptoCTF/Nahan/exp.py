from pwn import remote, process, context, info
from Crypto.Util.number import isPrime
from random import randrange
from tqdm import tqdm, trange
from ortools.sat.python import cp_model


def server_next_prime(n):
    while True:
        if isPrime(n):
            return n
        else:
            n += 1

def sat_solver(r, w, bitlen = 248):
    model = cp_model.CpModel()
    b = [model.NewBoolVar(f"b[{j}]") for j in range(bitlen)]
    model.add(b[0] == 1)  # Ensure the lsb is 1
    model.add(b[-1] == 1)  # Ensure the msb is 1
    for i, (r_i, w_i) in enumerate(zip(r, w)):
        x = []
        for j in range(bitlen):
            bit = (r_i >> j) & 1
            if bit == 0:
                # x_ij == b_j
                x.append(b[j])
            else:
                # x_ij == NOT b_j
                xj = model.NewBoolVar(f"x[{i},{j}]")
                model.Add(xj + b[j] == 1)
                x.append(xj)
        model.Add(sum(x) == w_i)

    solver = cp_model.CpSolver()
    status = solver.Solve(model)
    if status == cp_model.OPTIMAL or status == cp_model.FEASIBLE:
        s = 0
        for j in range(bitlen):
            if solver.Value(b[j]):
                s |= (1 << j)
        print("s =", hex(s))
        return s
    else:
        print("No solution found")
        return None

io = process(["python3", "nahan.py"])
secret = int(io.recvline().strip())
# info(f"Secret: {hex(secret)}")
l = 248
step = l // 2

rs = []
ss = []
ts = []
for i in tqdm(range(step)):
    while 1:
        s, t = randrange(2**(l//3), 2**(l//2)), randrange(2**(l//3), 2**(l//2))
        if all(3 * l > 6 * _.bit_length() > 2 * l for _ in (s, t)):
            r = int(server_next_prime(s * t ^ (2**l)))
            break
    rs.append(r)
    ss.append(s)
    ts.append(t)

info(f"Collecting {step} data samples...")
ws = []
for i in trange(step):
    io.sendlineafter(b"[Q]uit\n", b'g')
    io.sendlineafter(b"s, t: ", f"{ss[i]},{ts[i]}".encode())
    r = rs[i]
    io.recvuntil(b'n = ')
    n = int(io.recvline().strip())
    assert n % r == 0, "n is not divisible by r"
    w = int(n // r).bit_count() - 1 # the msb (2^248) of r is always 1, so we subtract 1
    ws.append(w)

info("Sat Solving...")
s_recovered = sat_solver(rs, ws)
io.sendlineafter(b"[Q]uit\n", b's')
io.sendlineafter(b"secret: \n", str(s_recovered).encode())
response = io.recvline()
print(response.decode())