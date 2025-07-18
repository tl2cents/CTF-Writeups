from Crypto.Signature import eddsa
from sage.all import GF, EllipticCurve, ZZ

p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
K = GF(p)
a = K(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec)
d = K(0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3)

E = EllipticCurve(K, (K(-ZZ(1)/ZZ(48)) * (a**2 + 14*a*d + d**2),K(ZZ(1)/ZZ(864)) * (a + d) * (-a**2 + 34*a*d - d**2)))

def to_weierstrass(a, d, x, y):
	return ((5*a + a*y - 5*d*y - d)/(12 - 12*y), (a + a*y - d*y -d)/(4*x - 4*x*y))

def to_twistededwards(a, d, u, v):
	y = (5*a - 12*u - d)/(-12*u - a + 5*d)
	x = (a + a*y - d*y -d)/(4*v - 4*v*y)
	return (x, y)

G = E(*to_weierstrass(a, d, K(0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A), K(0x6666666666666666666666666666666666666666666666666666666666666658)))

E.set_order(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed * 0x08)

print(f"{E = }")
print(f"{G = }")
# all points of order 8, i.e., 8 * G = O
torision_8 = E.zero().division_points(8)
print(f"{torision_8 = }")
ed_points = []
for point in torision_8:
    if point[0] == 0 or point[1] == 0:
        continue
    ed_points.append(to_twistededwards(a, d, point[0], point[1]))

print(f"{ed_points[2][1] = }")
pk = bytearray(int(ed_points[2][1]).to_bytes(32, 'little'))
# if not a valid point compression, flip the following bit
# pk[31] = pk[31] ^ (1 >> 7)

public_key = eddsa.import_public_key(encoded=pk)
# g = public_key._curve.G
# print(f"{g.xy = }")
print("Public Key:", public_key)
Q = 8 * public_key.pointQ
print(f"{(8 * public_key.pointQ).xy = }")