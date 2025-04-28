from pwn import remote
import re
import random
from sage.all import factor, ZZ, prod, GF, is_prime, gcd, discrete_log, crt
from tqdm import trange

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
    
def subgroup_generator(p, sub_order, randomize=True):
    assert (p-1) % sub_order == 0
    Fp = GF(p)
    g = Fp.primitive_element()** ((p-1) // sub_order)
    if randomize:
        x = random.randint(1, sub_order - 1)
        while gcd(x, sub_order) != 1:
            x = random.randint(1, sub_order - 1)
        return int(g ** x)    
    else:
        return int(g)
     
def find_target_generator(p, pp, order_base, randomize=True):
    assert (p-1) % pp == 0 and (pp - 1) % order_base == 0
    mod1 = int((p - 1) // pp)
    mod2 = pp
    r1 = 1
    r2 = subgroup_generator(pp, order_base, randomize)
    g = crt([r1, r2], [mod1, mod2])
    return g

good_primes = [670144747631070976739015819027954827310379693667090873445520193836663869580245599076670148076473491050020123654751096623483807617465722698994356143777563707,
               170953236075981703101107323627149749446399094948416530919519737926722425019602066485332700625463008928220692022155525741201814917060803040398296096589112909590796816127,
               7531993227394432935495469175847581786870840148535987047046105838996369558316042438597087283959689643904418638897096661950504686097925188166275662098492041069,
               35756093982019706426293639025599400558582772921867310666401488874611580043479377203647832136951529097764525162097024888170529918256990041464461134501152163496501126743211147409398847307]
target_p1_factors = [954622147622608228972957007162328813832449706078477027700171216291543973761033616918333544268480756481510147656340593480746164697244619229336689663500803,
                     85476618037990851550553661813574874723199547474208265459759868963361212509801033242666350312731504464110346011077762870600907458530401520199148048294556454795398408063,
                     746333058600320346363007250876692606705394386497818772002190431925918505580265798513385581050306147830402163981083696190101534492461869616158904290377729,
                     350549941000193200257780774760778436848850714920267751631387145829525294543915462780861099381877736252593383942127694982064018806441078837886873867658354544083344379835403405974498503]

target_pp1_smooth_factors = [
    3**320,
    139**36 * 163**34, # base 139**36
    2**502,
    11**127
]

really_small_bases = [3, 139 * 163, 2, 11]
inc_gap = [10, 1, 16, 4]
bases_power_ub = [320, 34, 502, 127]
solved_subgroups = {base: 0 for base in really_small_bases}
solved_dlogs = {1:0}
full_order =  1

while True:
    io = remote("1.95.137.123", 9999)
    mod = get_mod(io)
    assert is_prime(mod), "mod is not prime"
    Fp = GF(mod)
    print("mod:", mod)
    if mod not in good_primes:
        io.close()
        continue
    idx = good_primes.index(mod)
    p = good_primes[idx]
    pp = target_p1_factors[idx]
    order_base = really_small_bases[idx]
    expon0 = solved_subgroups[order_base]
    expon1 = expon0 + inc_gap[idx]
    mod0 = order_base**expon0
    mod1 = order_base**expon1
    x0 = solved_dlogs[mod0]
    g = int(find_target_generator(p, pp, mod1))
    while not set_lucky_number(io, g):
        g = int(find_target_generator(p, pp, mod1))
    assert pow(g, mod1, p - 1) == 1 
    assert pow(g, mod1//order_base, p - 1) != 1
    ticket = get_bet_ticket(io, 2)
    io.close()
    solved_dlog = False
    for i in trange(order_base**inc_gap[idx]):
        x1 = x0 + i * mod0
        expon = int(pow(g, x1, mod - 1))
        if pow(g, expon, mod) == ticket:
            print(f"found dlog:{x1} mod {mod1}")
            solved_dlogs[mod1] = x1
            solved_subgroups[order_base] = expon1
            solved_dlog = True
            break
    assert solved_dlog, "Error: No dlog"
    # lcm the trhe solved_subgroups
    full_order *= order_base**inc_gap[idx]
    print(f"full_order: {full_order.bit_length()}")
    if full_order >= 2**512:
        mods = []
        rs = []
        for base in really_small_bases:
            mod = base**solved_subgroups[base]
            r = solved_dlogs[mod]
            mods.append(int(mod))
            rs.append(int(r))
        x = crt(rs, mods)
        print(f"{x = }")
        print(int(x).to_bytes(512//8, "big"))
        break