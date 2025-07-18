from pwn import remote, process, context, log
from math import gcd, prod
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import EllipticCurve, GF, Zmod, factor, euler_phi, ZZ
from multiprocessing import Process, Queue

def try_factor(n, time_limit=20):
    def worker(n, result_queue):
        try:
            result_queue.put(factor(n))
        except Exception as e:
            result_queue.put(e)
    result_queue = Queue()
    p = Process(target=worker, args=(n, result_queue))
    p.start()
    p.join(timeout=time_limit)
    
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    
    if not result_queue.empty():
        result = result_queue.get()
        if isinstance(result, Exception):
            raise result
        return result
    return None

# nc 91.107.161.140 11177
local = False
io = remote('91.107.161.140', 11177) if not local else process(["sage", "sobata.sage"])
# io = process(["sage", "sobata.sage"])

# context.log_level = 'debug'

def get_enflag(io: remote = io):
    io.sendlineafter(b"[Q]uit\n", b"e")
    flag = io.recvline().decode().strip().split(': ')[1]
    return eval(flag)

def walk(x: int, y: int, io: remote = io):
    io.sendlineafter(b"[Q]uit\n", b"w")
    io.sendlineafter(b'desired point over E: \n', f"{x},{y}".encode())
    return eval(io.recvline().decode().strip().split(': ')[1])

def jump(x: int, y: int, n: int, io: remote = io):
    io.sendlineafter(b"[Q]uit\n", b"j")
    io.sendlineafter(b'desired point over E: \n', f"{x},{y}".encode())
    io.sendlineafter(b'jump over the given point: \n', str(n).encode())
    return eval(io.recvline().decode().strip().split(': ')[1])

def get_curve_from_points(ec_points):
    # y^2 = x^3 + a*x + b
    # a = 0
    bs = [y**2 - x**3 for x, y in ec_points]
    ns = [bi - bs[0] for bi in bs[1:]]
    p = gcd(*ns)
    assert isPrime(p), "p is not prime"
    b = bs[0] % p
    return p, b

while True:
    encflag = get_enflag(io)
    log.info(f"Encrypted flag: {encflag}")
    points = [encflag]
    for i in range(8):
        x, y = walk(points[-1][0], points[-1][1], io)
        points.append((x, y))
    a = 0
    p, b = get_curve_from_points(points)
    log.info(f"Curve parameters: p={p}, a={a}, b={b}")
    E = EllipticCurve(GF(p), [a, b])
    q = E.order()
    q_facs = factor(q, limit = 2**28)
    log.info(f"Order of the curve: {q = }")
    print(f"Order of the curve: {q_facs}")
    q_max = q_facs[-1][0]
    factors = try_factor(q_max)

    if factors is None:
        print("Failed to factor the order of the curve")
        io.close()
        io = remote('91.107.161.140', 11177) if not local else process(["sage", "sobata.sage"])
        # io = remote('91.107.161.140', 11177)
        continue
    else:
        log.info(f"Successfully factored q_max factors: {factors}")
    q_facs = list(q_facs[:-1]) + list(factors)  # Replace the last factor with the factors we found
    a1s = GF(p)(1).nth_root(3, all = True)
    b1s = GF(p)(1).nth_root(2, all = True)
    
    phi_q = prod([pi**ei - pi**(ei-1) for pi,ei in q_facs])
    log.info(f"Euler's totient function: {phi_q}")
    x0, y0 = jump(encflag[0], encflag[1], phi_q - 1, io)
    log.info(f"{x0 = }")
    for a1 in a1s:
        flag = long_to_bytes(int(pow(a1, -1, p) * x0 % p))
        print(f"Flag candidate: {flag = }")
    break
