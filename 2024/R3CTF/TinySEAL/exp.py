import tenseal.sealapi as sealapi
import base64
import os
from tqdm import tqdm
from compute_trace import gens, sub_group
from pwn import remote, log

poly_modulus_degree = 4096
plain_modulus = 163841

flag = os.getenv('FLAG')


def gen_keys():
    parms = sealapi.EncryptionParameters(sealapi.SCHEME_TYPE.BFV)
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_plain_modulus(plain_modulus)
    coeff = sealapi.CoeffModulus.BFVDefault(
        poly_modulus_degree, sealapi.SEC_LEVEL_TYPE.TC128)
    parms.set_coeff_modulus(coeff)

    ctx = sealapi.SEALContext(parms, True, sealapi.SEC_LEVEL_TYPE.TC128)

    keygen = sealapi.KeyGenerator(ctx)
    public_key = sealapi.PublicKey()
    keygen.create_public_key(public_key)
    secret_key = keygen.secret_key()

    parms.save("./app/parms")
    public_key.save("./app/public_key")
    secret_key.save("./app/secret_key")


def load():
    parms = sealapi.EncryptionParameters(sealapi.SCHEME_TYPE.BFV)
    parms.load("./parms")

    ctx = sealapi.SEALContext(parms, True, sealapi.SEC_LEVEL_TYPE.TC128)

    public_key = sealapi.PublicKey()
    public_key.load(ctx, "./public_key")
    
    return ctx, public_key


def gen_galois_keys(ctx, secret_key, elt):
    keygen = sealapi.KeyGenerator(ctx, secret_key)
    galois_keys = sealapi.GaloisKeys()
    keygen.create_galois_keys(elt, galois_keys)
    galois_keys.save("./galois_key")
    return galois_keys


def gen_polynomial(a):
    poly = hex(a[0])[2:]
    for i in range(1, len(a)):
        poly = hex(a[i])[2:] + 'x^' + str(i) + ' + ' + poly
    return poly


def check_result(ctx, decryptor, target):
    plaintext = sealapi.Plaintext()
    ciphertext = sealapi.Ciphertext(ctx)
    ciphertext.load(ctx, "./computation")
    decryptor.decrypt(ciphertext, plaintext)
    assert plaintext.to_string() == target.to_string()


def send(filepath):
    f = open(filepath, "rb")
    data = base64.b64encode(f.read()).decode()
    f.close()
    print(data)


def recv(filepath):
    try:
        data = base64.b64decode(input())
    except:
        print("Invalid Base64!")
        exit(0)

    f = open(filepath, "wb")
    f.write(data)
    f.close()

def list_methods(obj):
    all_attributes = dir(obj)
    methods = [attribute for attribute in all_attributes if callable(getattr(obj, attribute))]
    return methods


ctx, public_key = load()
encryptor = sealapi.Encryptor(ctx, public_key)
elt = gens

io = remote('ctf2024-entry.r3kapig.com', 30800)

io.recvuntil(b'Here Is Ciphertext:\n')
raw_line = io.recvline().strip()
data = base64.b64decode(raw_line)
f = open("./ciphertext", "wb")
f.write(data)
f.close()

ciphertext = sealapi.Ciphertext(ctx)
ciphertext.load(ctx, "./ciphertext")


io.recvuntil(b"Please give me your choice:")
inp = b" ".join([str(elt[j]).encode() for j in range(6)])
io.sendline(inp)
log.info(io.recvline().decode())

data = base64.b64decode(io.recvline().strip())
f = open("./galois_key", "wb")
f.write(data)
f.close()

galois_keys = sealapi.GaloisKeys()
galois_keys.load(ctx, "./galois_key")

evaluator = sealapi.Evaluator(ctx)
target_ciphertext = ciphertext

for i in tqdm(range(3, 4096 * 2 , 2)):
    ciphertext = sealapi.Ciphertext(ctx)
    ciphertext.load(ctx, "./ciphertext")
    res = 1
    exps = sub_group[i]
    # print(f"Computing {i}: {exps}")
    for j in range(len(exps)):
        res *= elt[j] ** exps[j] 
        res %= (4096 * 2)
        for _ in range(exps[j]):
            evaluator.apply_galois_inplace(ciphertext, elt[j], galois_keys)
    assert res == i, f"Failed at {i}: {res = }"
    # add ciphertext
    evaluator.add_inplace(target_ciphertext, ciphertext)

# mul target_ciphertext with constant value `mul`
mul = pow(4096, -1, plain_modulus)
plaintext_mul = sealapi.Plaintext(hex(mul)[2:])
evaluator.multiply_plain_inplace(target_ciphertext, plaintext_mul)
target_ciphertext.save("./computation")
f = open("./computation", "rb")
data = base64.b64encode(f.read()).decode()
f.close()
io.sendlineafter(b"Give Me Your Computation\n", data.encode())
print(io.recvline().decode())