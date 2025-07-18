from pwn import remote, process, context, log
from math import gcd, prod
from Crypto.Util.number import isPrime, long_to_bytes, bytes_to_long
from sage.all import EllipticCurve, GF, Zmod, factor, euler_phi, ZZ, PolynomialRing, discrete_log_lambda
from multiprocessing import Process, Queue

def try_factor(n, time_limit=15):
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

local = False



# io = process(["sage", "server.sage"])

# context.log_level = 'debug'

def get_enflag(io: remote):
    io.sendlineafter(b"[Q]uit\n", b"e")
    flag = io.recvline().decode().strip().split(': ')[1]
    return eval(flag)

def walk(x: int, y: int, io: remote):
    io.sendlineafter(b"[Q]uit\n", b"w")
    io.sendlineafter(b'desired point over E: \n', f"{x},{y}".encode())
    return eval(io.recvline().decode().strip().split(': ')[1])

def jump(x: int, y: int, n: int, io: remote):
    io.sendlineafter(b"[Q]uit\n", b"j")
    io.sendlineafter(b'desired point over E: \n', f"{x},{y}".encode())
    io.sendlineafter(b'jump over the given point: \n', str(n).encode())
    return eval(io.recvline().decode().strip().split(': ')[1])

def get_curve_from_points(ec_points):
    # y^2 = x^3 + 0*x + d
    ds = [(y**2 - x**3) % mod_poly for x, y in ec_points]
    ns = [di[0] - ds[0][0] for di in ds[1:]]
    p = gcd(*ns)
    assert isPrime(p), "p is not prime"
    b = ds[0] % p
    return p, b

while True:
    R = PolynomialRing(ZZ, "g")
    g = R.gen()
    mod_poly = g**2 + 13 * g + 37
    # context.log_level = 'debug'
    io = remote('91.107.252.0', 11173) if not local else process(["sage", "sobata_II.sage"])
    mod_poly = g**2 + 13 * g + 37
    encflag = get_enflag(io)
    log.info(f"Encrypted flag: {encflag}")
    points = [encflag]
    for i in range(8):
        x, y = walk(points[-1][0], points[-1][1], io)
        points.append((x, y))
        
    a0 = 0
    p, d = get_curve_from_points(points)
    log.info(f"Curve parameters: p={p}, a={a0}, b={d}")
    log.info(f"Partial factors of p - 1: {factor(p - 1)}")

    F = GF((p, 2), name="g", modulus=mod_poly)
    g = F.gen()
    f_order = F.order()
    log.info(f"Finite field: {F}")
    E = EllipticCurve(F, [a0, d])
    q = E.order()
    E.set_order(q)
    q_facs = factor(q, limit = 2**28)
    log.info(f"Order of the curve: {q = }")
    assert q * E(encflag) == 0, "Not valid"
    log.info(f"Partial factors of q: {q_facs}")
    q_max = q_facs[-1][0]
    factors = try_factor(q_max)

    if factors is None:
        print("Failed to factor the order of the curve")
        io.clean()
        io.close()
        # io = remote('91.107.252.0', 11173) if not local else process(["sage", "sobata_II.sage"])
        continue
    else:
        log.info(f"Successfully factored q_max factors: {factors}")
    q_facs = list(q_facs[:-1]) + list(factors)
    smooth_bound = 2**46
    smooth_factors = [(pi, ei) for pi, ei in q_facs if pi < smooth_bound]
    smooth_subgroup = prod([pi**ei for pi, ei in smooth_factors])
    log.info(f"Smooth subgroup: {smooth_subgroup}, {smooth_subgroup.bit_length()} bits")

    if smooth_subgroup < 2**(196 - 40):
        log.warning("Smooth subgroup is smaller than p/2^40")
        io.clean()
        io.close()
        # io = remote('91.107.252.0', 11173) if not local else process(["sage", "sobata_II.sage"])
        continue

    a1s = F(1).nth_root(3, all = True)
    b1s = F(1).nth_root(2, all = True)
    # exlude the trivial roots 1
    a1s = [a for a in a1s if a != F(1)]
    b1s = [b for b in b1s if b != F(1)]
    log.info(f"Cube roots of unity: {a1s}")
    log.info(f"Square roots of unity: {b1s}")

    phi_q = prod([pi**ei - pi**(ei-1) for pi,ei in q_facs])
    log.info(f"Euler's totient function: {phi_q}")
    x0, y0 = jump(encflag[0], encflag[1], phi_q - 1, io)
    log.info(f"{x0 = }")

    gens = E.gens()
    is_ok = False
    for gen in gens:
        gen_order = gen.order()
        gen_order_facs = factor(gen_order)
        smooth_factors = [(pi, ei) for pi, ei in gen_order_facs if pi < smooth_bound]
        smooth_subgroup = prod([pi**ei for pi, ei in smooth_factors])
        log.info(f"Smooth: {smooth_subgroup.bit_length()} bits")
        if smooth_subgroup >= 2**(196 - 40):
            is_ok = True
            smooth_gen = (gen_order // smooth_subgroup) * gen
            smooth_gen.set_order(smooth_subgroup)
            break
        smooth_gen = (gen_order // smooth_subgroup) * gen
        smooth_gen.set_order(smooth_subgroup)
        
    if not is_ok:
        log.warning("No suitable generator found for the attack")
        io.clean()
        io.close()
        # io = remote('91.107.252.0', 11173) if not local else process(["sage", "sobata_II.sage"])
        continue

    a1_found = False
    for a1 in a1s:
        for b1 in b1s:
            gx_, gy_ = (smooth_gen[0] / a1, smooth_gen[1] / b1)
            px, py = walk(gx_, gy_, io)
            P = E(px, py)
            try:
                log.info(f"Trying point: {P}")
                c0 = P.log(smooth_gen)
                print(f"c0 = {c0}")
                a1_found = True
                break
            except Exception as e:
                # log.error(f"Failed to compute log: {e}")
                continue
        if a1_found:
            break

    # k * smooth_subgroup + c0 = c
    # (k * smooth_subgroup + c0)g = P
    # k * (smooth_subgroup * g) = P - c0 * g
    new_g = smooth_subgroup * smooth_gen
    new_p = P - c0 * smooth_gen
    bound = 2**(196) // smooth_subgroup + 1
    log.info(f"lambda Bound: {int(bound).bit_length()} bits")
    k = discrete_log_lambda(new_p, new_g, [ZZ(0), ZZ(bound)], operation="+")
    c = int(k) * int(smooth_subgroup) + int(c0)
    log.info(f"c = {c}")
    assert c * smooth_gen == P
    
    log.info(f"{encflag = }")
    log.info(f"{E = }")
    q = E.order()
    cg = gcd(c, q)
    c_inv = pow(c//cg, -1, q)
    log.info(f"cg = {cg}")
    flag_pt = c_inv * E(encflag)
    if cg == 1:
        flag_pts = [flag_pt]
    else:
        flag_pts = flag_pt.division_points(cg)
        
    for flag_pt in flag_pts:
        fx, fy = (flag_pt[0]/a1, flag_pt[1]/b1)
        print(f"{fx = }")
        print(f"{fy = }")
        print(long_to_bytes(int(fx[0])))