from sage.all import BooleanPolynomialRing, GF, Sequence, Ideal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

with open('aes.txt', 'r') as f:
    cir_lines = f.readlines()[3:]

with open("wires_truth.txt", "r") as f:
    wires_truth = f.readlines()

with open("flag_enc_hex.txt", "r") as f:
    flag_enc = bytes.fromhex(f.read().strip())

R = BooleanPolynomialRing(128, [f'x_{i}' for i in range(128)])
F2 = GF(2)
xlist = list(R.gens())
all_wires = [F2(0)] * 128 + xlist
all_wires += [None] * 40000

for line in wires_truth:
    if line.startswith("Input Wire"):
        idx, bit = line[10:].strip().split(":")
        all_wires[int(idx.strip())] = F2(int(bit.strip() == "true"))

eqs = []

for i, line in enumerate(cir_lines):
    if line.strip() == "":
        continue
    ops = line.split()
    if ops[-1] == "XOR":
        assert len(ops) == 6
        input1 = int(ops[2])
        input2 = int(ops[3])
        output = int(ops[4])
        if all_wires[input1] is None:
            continue
        if all_wires[input2] is None:
            continue
        if all_wires[output] is not None:
            if all_wires[input1] in F2 and all_wires[input2] in F2 and all_wires[output] in F2:
                assert all_wires[input1] + all_wires[input2] == all_wires[output]
                continue
            print(f"XOR Equation {i}: {all_wires[input1]} + {all_wires[input2]} = {all_wires[output]}")
            eqs.append(all_wires[input1] + all_wires[input2] - all_wires[output])
        else:
            all_wires[output] = all_wires[input1] + all_wires[input2]
    elif ops[-1] == "INV":
        assert len(ops) == 5
        input1 = int(ops[2])
        output = int(ops[3])
        if all_wires[input1] is None:
            continue
        if all_wires[output] is not None:
            # discard trivial solutions
            if all_wires[input1] in F2 and all_wires[output] in F2:
                assert all_wires[input1] == F2(1) + all_wires[output]
                continue
            print(f"INV Equation {i}: {all_wires[input1]} = {1 + all_wires[output]}")
            eqs.append(all_wires[input1] - F2(1) - all_wires[output])
        else:
            all_wires[output] = F2(1) + all_wires[input1]
    elif ops[-1] == "AND":
        assert len(ops) == 6
        input1 = int(ops[2])
        input2 = int(ops[3])
        output = int(ops[4])
        if all_wires[input1] is None:
            continue
        if all_wires[input2] is None:
            continue
        # print("AND", all_wires[input1], all_wires[input2])
        if all_wires[output] is not None:
            if all_wires[input1] in F2 and all_wires[input2] in F2 and all_wires[output] in F2:
                assert all_wires[input1] * all_wires[input2] == all_wires[output]
                continue
            if all_wires[input1] in F2 or all_wires[input2] in F2:
                print(f"AND Equation {i}: {all_wires[input1]} * {all_wires[input2]} = {all_wires[output]}")
                eqs.append(all_wires[input1] * all_wires[input2] - all_wires[output])
        # not add AND info to make all eqs linear
        else:
            if all_wires[input1] in F2 or all_wires[input2] in F2:
                all_wires[output] = all_wires[input1] * all_wires[input2]
    else:
        print(ops)
        break

print(len(eqs))
seq = Sequence(eqs)
mat, mono = seq.coefficients_monomials()
print(seq.nvariables())
print(seq.variables())
assert mat.rank() == seq.nvariables(), "rank not equal to nvariables, sol not unique"
basis = mat.right_kernel().basis()
assert len(basis) == 1
sol = basis[0]
assert sol[-1] == 1 and mono[-1] == 1
unknown_vars = [xi for xi in xlist if xi not in seq.variables()]
unknown_nvar = len(unknown_vars)
sol_dict = {xi:b for xi, b in zip(mono[:-1], sol[:-1])}

for i in range(2**unknown_nvar):
    for j, xi in enumerate(unknown_vars):
        sol_dict[xi] = (i >> j) & 1
    key_bin_str = "".join([str(sol_dict[xi]) for xi in xlist])
    key_bytes = int(key_bin_str, 2).to_bytes(16, byteorder='big')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    flag = cipher.decrypt(flag_enc)
    print(flag)