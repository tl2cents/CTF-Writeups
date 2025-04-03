from sage.all import ZZ

def count_msb_errors(d, d_bar, nmsb=600):
    return bin(d ^ d_bar)[2:].zfill(1024)[:nmsb].count('1')

n = 0x639d87bf6a02786607d67741ebde10aa39746dc8ed22b191ff2fefe9c210b3ee2ce68b185dc7f8069e78441bdec1d33e2b342c226b5cde8a49f567ac11a3bcb7ff88eeededdd0d50eb981635920d2380a6b878d327b261821355d65b2ef9f807035a70c77252d09787c2b3dfafdfa4f5c6b39a1c66c5b39fe9d1ee4b36d86d5
e = 0x10001
flag = 0x40208a7900b1575431a49690030e4eb8be6269edcd3c7b2d97ae94a6eb744e9c622d81b95ea45b23ee6e0d773e3dd48adc6bb2c7c6423d8fd52eddcc6c0710f607590d5fc57a45883a36ad0d851f84d4bee86ffaf65bc1773f97430080926550dce3666051befa87bacc01d44dd09baa6ae93a85cedde5933f7cbbe2cb56cdd
d = 0x1a54893799cd9805600cfaee1c8a408813525db268fbc29e7f2a81eb47b64d2dd20dc8be52b6332e375f92a120957042a92a4bd4f5e13ef14e9b398bec330602dc9dbbb63cf3dfe6d33bf95d08306a894b052e005a57cc41673fe866f4f8b2ffb0aa26fc4c51a8f5135e40df2107e0259ddf4c1d9c1eb41b1f702b135c941

# cc = (p - 1)(q-1) / lcm(p-1, q-1)
cc_max = n // d
nmsb = 520

for k in range(1, e):
    for cc in range(2, cc_max, 2):
        # ed = k(n - p - q + 1)/cc + 1
        d_real_msb = (k * n // cc + 1) // e
        err_num = count_msb_errors(d, d_real_msb, nmsb)
        if err_num <= 16:
            err_pos = [i for i, (a, b) in enumerate(zip(bin(d)[2:].zfill(1024)[:nmsb], bin(d_real_msb)[2:].zfill(1024)[:nmsb])) if a != b]
            print(f"Found: {d_real_msb = } with {k//cc = }")
            print(f"Found: {err_num =  } in {nmsb} msb bits")
            print(f"Found: {err_pos = } from highest bit to lowest bit")
            exit(0)

# Found: d_real_msb = 4514088967547488951649479902515202812774123491743896551436762406242971627370506765191178449599877062466101307468179199203541042200279058948411943214043223303232663400817011215091948406144006044666676764127646300202138127044251756808659462372075867443194976482310771190867332273026020227834408536297872091 with k//cc = 67
# Found: err_num =  9 in 520 msb bits
# Found: err_pos = [46, 102, 235, 252, 280, 394, 412, 434, 485] from highest bit to lowest bit