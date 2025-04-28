from pwn import remote
import re
from sage.all import factor, ZZ, prod, GF, is_prime, gcd, discrete_log

def get_mod(io: remote) -> int:
    io.sendlineafter(b"What do you do? ", b"1")
    io.recvuntil(b"lucky number is ")
    mod = int(io.recvline().decode().strip().split(".")[0])
    return mod

def set_lucky_number(io: remote, lucky_number: int):
    io.sendlineafter(b"What do you do? ", b"2")
    io.sendlineafter(b"You decide to pick your own lucky number: ", str(lucky_number).encode())
    response = io.recvline().decode().strip()
    return "successfully" in response

def get_bet_ticket(io: remote, bet_size: int):
    io.sendlineafter(b"What do you do? ", b"3")
    io.sendlineafter(b"You decide to pick your bet size: ", str(bet_size).encode())
    # re to extract from "You take the ticket with the number {ticket} from the machine"
    response = io.recvline().decode().strip()
    ticket = re.search(r"number (\d+)", response).group(1)
    return int(ticket)

def set_lucky_number_and_bet(io: remote, p: int, g: int, x: int, times: int):
    io.sendlineafter(b"What do you do? ", b"4")
    io.sendlineafter(b"I don't think the boss's lucky number is lucky enough: ", str(p).encode())
    io.sendlineafter(b"Yes!\" I whisper, overriding the preset algorithm with my own: ", str(x).encode())
    io.sendlineafter(b"You decide to pick your own lucky number: ", str(g).encode())
    io.sendlineafter(b"You decide to pick your bet size: ", str(times).encode())
    response = io.recvline().decode().strip()
    if "You take the ticket with the number" in response:
        ticket = re.search(r"number (\d+)", response).group(1)
        return int(ticket)
    else:
        print("Error: ", response)
        return None


solved_prime = {}
solved_subgroups = {}
solved_dlogs = {}
while True:
    io = remote("1.95.137.123", 9999)
    mod = get_mod(io)
    assert is_prime(mod), "mod is not prime"
    Fp = GF(mod)
    print("mod:", mod)
    print("solved_prime:", solved_prime)    
    if mod in solved_prime:
        io.close()
        continue
    solved_prime[mod] = True
    facts = factor(mod - 1)
    print("factors:", facts)
    sub_groups = []
    for p, e in facts:
        if p.bit_length() >= 50:
            continue
        if p not in solved_subgroups:
            solved_subgroups[p] = e
            sub_groups.append(p ** e)
        elif solved_subgroups[p] < e:
            solved_subgroups[p] = e
            sub_groups.append(p ** e)
    # solve the dlog for each subgroup
    sub_order = prod(sub_groups)
    print("sub_groups:", sub_groups)
    g = Fp.primitive_element()
    # g_order = mod - 1
    g_order = g.multiplicative_order()
    g_sub0 = g ** (g_order // sub_order)
    assert g_sub0.multiplicative_order() == sub_order
    g_sub = None
    for i in range(1, sub_order):
        if gcd(i, sub_order) == 1:
            if set_lucky_number(io, g_sub0**i):
                g_sub = g_sub0 ** i
                print("g_sub:", g_sub, "success")
                break
    if g_sub is None:
        print("Error: No good lucky number found")
        io.close()
        continue
    y_sub = get_bet_ticket(io, 1)
    print("y_sub:", y_sub)
    order_y_sub = Fp(y_sub).multiplicative_order()
    print("order_y_sub:", order_y_sub)
    r = discrete_log(Fp(y_sub), Fp(g_sub), ord=sub_order)
    print(f"x mod {sub_order} = {r}")
    solved_dlogs[sub_order] = r
    print("solved_dlogs:", solved_dlogs)