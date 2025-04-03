import os
import json
import signal
from sage.crypto.boolean_function import BooleanFunction
from itertools import combinations
from tqdm import tqdm
import secrets
from chall import Cipher, LFSR, Cipher256

MASK1 = int(0x6D6AC812F52A212D5A0B9F3117801FD5)
MASK2 = int(0xD736F40E0DED96B603F62CBE394FEF3D)
MASK3 = int(0xA55746EF3955B07595ABC13B9EBEED6B)
MASK4 = int(0xD670201BAC7515352A273372B2A95B23)
    
class LFSRSymbolic:
    def __init__(self, n, key, mask):
        assert len(key) == n, "Error: the key must be of exactly 128 bits."
        self.state = key
        self.mask = mask
        self.n = n
        self.mask_bits = [int(b) for b in bin(self.mask)[2:].zfill(n)]
        
    def update(self):
        s = sum([self.state[i] * self.mask_bits[i] for i in range(self.n)])
        self.state = [s] + self.state[:-1]
        
    def __call__(self):
        b = self.state[-1]
        self.update()
        return b
    
class CipherSymbolic:
    def __init__(self, key: list):
        self.lfsr1 = LFSRSymbolic(128, key[-128:], MASK1)
        self.lfsr2 = LFSRSymbolic(128, key[-256:-128], MASK2)
        self.lfsr3 = LFSRSymbolic(128, key[-384:-256], MASK3)
        self.lfsr4 = LFSRSymbolic(128, key[-512:-384], MASK4)
        
    def filter_polynomial(self, x0, x1, x2, x3):
        # x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x1 + x2
        return x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x1 + x2

    def bit(self):
        x,y,z,w = self.get_xyzw()
        return self.filter_polynomial(x, y, z, w)
    
    def get_xyzw(self):
        x = self.lfsr1() + self.lfsr1() + self.lfsr1()
        y = self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3() + self.lfsr3()
        w = self.lfsr4() + self.lfsr4()
        return x,y,z,w
    
    def get_yz(self):
        y = self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3() + self.lfsr3()
        return y,z
    
    def stream(self, n):
        return [self.bit() for _ in range(n)]
            
    def xor(self, a, b):
        return [x + y for x, y in zip(a, b)]

    def encrypt(self, pt: bytes):
        pt_bits = [int(b) for b in bin(int.from_bytes(pt, 'big'))[2:].zfill(8 * len(pt))]
        key_stream = self.stream(8 * len(pt))
        return self.xor(pt_bits, key_stream)
    
key = secrets.randbits(512)
key_bits = [int(i) for i in bin(key)[2:].zfill(512)]
br512 = BooleanPolynomialRing(512, [f"x{i}" for i in range(512)])
key_sym = list(br512.gens())

cipher = Cipher(key)
cipher_sym = CipherSymbolic(key_sym)

pt = b"\x00" * 2**12
ct = "a790f917b594f5751b83a7b901f87680093b2eab35e375b2045b1cbba9052c431d7a21da43c3d52cebb583b67c5a4eb99a2e882fea0e1800a1993fcaafba4ce517bdf6c80ad8d1b5737ed80777ee581a21182bfc387f63841555652bbce45d6262c4f767c4faf7c5ad5b60c0c4253b316485e3a91ebc6d5a75dd940a935f3967a91812e75968c8b3f3bd0ce983dbc1f2166c063cb175b5447e76de7237aec59c33713e19defa2d75759e6f8175308e72618d7ade2deaf43c2c47f8eabcfaa39a471069979f0fb175a555c7f8369df7fda8181924e7eb3ef87f14336783e95fcac285902c14c3af485809d4139ac34ac5233c9a4e1e30873e3a5479e38496319b8f9e9f803b1fa73f75660278ac3c3c482a1943a40374f77767892b3a4bee959cd9100434d05a1b8f846429e4c80b040b2636fe8d7a4c8843c0ec8d74a1b145de81a87077b092d083388236c9b60dbbf7495d618855354f5c612be152cbaf41a56f7c7b452d8343f00c06baeaf7de5146366fb3b5ebc68ee3c2e6eef46a7e5306c2acc613afcf55a85ef319bb4c1333b5c057a1282abad88f23a1b216205791ca250dc3054df98412e5abf00578806d632577f98645de35d6f98dcc67795d45abbeac3db7c02e55c6b01375ca7fb4f74ea5c68e5539996de57b1282cce2e1775bffa5bc5d3a033f161572c979a92d83a8ec0c3b938d1c91983a1b14124a49ef893ea4685c9796a3c8b9dcf396b8c63b736de9f87ab57ede64ddd16430f53d7a8c1f91bab1976694e72f92d133264d41ce40f4806c0c57902d05d0660388805bf890fa3740ce87833a0fc2e23b52e816af7d2cc2661543d23ed33a1fc01d5d58fcb2db1e75790a6b06cc1f8921d94cefb2c1bc7c4415442a979b30ffbb0e8390c8e6bc6a3076777959522ea7d053d81671de01fd123d11960250ac517004afa1b375ea5cafe60bb5bdb8fef151a1dc068494a582616fa0460ff03f98e9c867edec107cdbdee478b42182cd598ebba1e01e992bf6e83009c4db6d28e63ed3b5b7944c64976a81c187b4a8c0423bb805ec61bb6f138afc4f146628e55486d3d6949554a7af3eeaec1376b8af320a20035bedff56d358345a85beca00c13fbf1e14e760503270294e3f4f8a330016a77f72fc5ca1c6401707337e334a191fca7fef47e61a9f750dd00200170b06887a866175a87c2e566591e1cf147f41a7dd837d9e045c62f8fb8f0bc6ee983dc6409ec2bf13f133e6bcf1ad904318d029e381f5c48613cb6f49f999a3c13850101bfaa39e6754636e7108485572b46cd140a034fa1d37d4d6b12fad7445dc8310173110a8b8cb3b4cd520593f9e6cd26e83f6a4d8319d59b3b576be8c46c223229f37e72eb6cc83bd9e66576dbfb7a9078c03af211276f35c27d6d3c570438126df32ae9dd13f0f8e8809ae0949c7fe897b87b5e311950147e9f16a88b14bc60ab2ca34ce6b249dd26f224a896f01a6c4adea6bfd33f96f030d52eb6676ba26c09b49119fee3e77191cd282387059ba2883de8c017ba67fe40cd16cd38486237930dd8dc7efb0513c68c3d4335b81201693e6ac148c9afb9c02096f0467f4f3c96841d37a0c23a252d5752f60af0ad3db8f15b48819effd7f4af27a60c966f49a0946cb878c50e640a560ad974ea3b577f76e15b4cc0743f28d4a81f7556715fb159504c904a8cd3635c49fba984e8b8880023813ee6d0ef04a4a778fbbd2c1b8862b69f31e5f4ef35d4e0a71dfeb519e3b3a1e672c31e4dfa5b09459b169aec350280cf65decb8c9e0726ac030b9b3aa91e236010742f63f8fc8d8f3de7aa013b198768c100ca1823a6146932e91c4c916cc614645a870ecd6833428df94c3a55c8a7244a8d61fb703175313456e3dabf8f580057e72a3057a3551ba7d572d336586ca7c237259ddbfe786a626c8060b586e8c42b9598ba82a5945af032ef0f22bcf93e45f56f7bf4b7bce735b24a37cdd5d1c7400e96a4de3a533dba8178f4329d1be4d3f2d99147da8d35607d2e4f823459a0595833b2adf0ee55ddf0c358bc4bfbc83d4b9bed97e5521fac784423e28dd5df72c9c271580a86e2a1d3ab599310e6d605fa56a7d797b6ed36be3d0579da2913e4eb7d7f97d094ee970aefabbb0d79d304fde0b70cb48e531298c9a5f8d84d132f301521367740d0b83e99aa40338fb22c6ad0c947e1c7f3e48ed8fb3bb00396af0c0eab9dfcb260432036724926aab9fb8c34894e44676fffe08ecb63d24abc796e20a67519ab9922e933e993644d75ea8f7ab6e7bdc4748012e67631f2f5bae6f4a81b07fd58d9d29d604499bd44aa9ed7c039769558e4e8ccab170f1974e5fcb54a5cb17e3d6b7d98cdb4730701a8975f6f26c4185b08bf9aa90cbb1c2d9bf3b720eec7b27417400ae302563cf53e0201bf81a88aaa5006b57941e29ba47491407c81dc007668bfb7885cf930d0cfd38c17758e779b9469d41a494511f1b738a2da86e975dc07ac9eb6f7342e1655091f8834f590e2630528a8feabcfdaee1d2cf4f49d5cf48392395238836dfbb6835afa5508678735b12d7cfded20d4242589b5c025f062a81aedd608a11f52dfecd02bd58c6d3233104a2b97b4c6b7f5059c0ecc8bf91da32a3915c593aa24b6a9e20bcfd48f982e00a91a6198074deeffbf22a6b56346d9895b5354091482d0776c37175144ca38f6002be755737c1233185a10251463e711435bf6c1034285497650c583ff370bee675a1653076ce4215dcf6b74019925dcd99194a0b46413e7201a69acee4975026f05daf95943ff27f13ce9017bfa964ef416ab7f1f109b5007e6b1ff82c277ebcc421cdfcead5e72d1d0c18a2cd132238128d8f4c2d17f123b04cc4af68b75379e80471b868875bd05c7ef6f4d194793260fc4442f41b5d40190b7e5c911448ddbd532ae9aa0fd6dc8d63b973188c40d88ccecbcdf995e935dacd7e50c7a16a66c60b65f72107c863ac6d60a3bdce99d06f56387c3498cfaca6b7ab688b364955b11d5d7ef05225b65181f58d582883b349ecc842ae14c8ffb1051e2c5332039a066497c780cdf039c66a2dba90e890b77620dc7e829e223fdf7e96505693cd70fb0431327825721061aa1b67c2438504a25e6d10b7938015e0be2be1ab80496ea28e7bd7ee2a931338cdb8e6c0766eac7a6489f3fc90b298bd3033d711bb7ec95d910834b7ec6935be420c52b6fa94045030ea92cbb9f708c7dc8288965b1e3683d1058f9c5a0d3aabc6b415a8fb5fdd98670d2e49958848010ce5bd297ad7870c36d2d5a1d92807ce0dafb1de6b9e50548af121865635534ecc1a5cb4c26f4af5f8ea19d2bc4315b23ef4531c39439801f9790293c79d3215f7f4de25516a78b1cf04bdce06e46b9a238b75104f5a6c79d3a73d5decb2f88af74a42cae3dc8a0a58dab27b81f496e0aca9cd820e4c92de8bfd3481567f83cd0b203875babd18ca99272d431dab864e19748a05f0414a8ee400d943e891f08336592d9a1a732d7d6cdb99bfa9b0f5ad49052004b3289a9e6f1a363e4a34c15accd1d63673a6ed5bf672fb24a184794980af075bf448e4f58426f1094583ac8ea39da417376687e6fa449344131f2ce38768a335df1e9008675ef1c40cfb7c0f1873086d4ee255fe0e3cca5bd34c15e44ccc377979d1005b33bc389eaaad1f892a1dd3cdfc014d315f52efcf95142cf2fcee6bfb40872ce8fd412fc0fa0b0be59813d9f587d961aa2a9eaf15eb0bf78dca8e6a64543cc423bea182e9326d20f07746f89ce30cadaf1fa17176bb00d92031ab4e3ab8d23b2bbf6683e360508e394ac542a45efc3a997f6f7909383e0dbde3042e2ec6eeca4a58bb15901b7fe20f93c5ce879dbda27ed660884aac5c61c0014894507b64aae26027e1976af5e0b7c585ce27737a6095d81fa069768c12dadd97810d362fb99f795e78553deff6112ea30176e1fd4798f7791e64144927a3051d3aa5356d803e2e04cecf1524400b87f1e2ae0f379f8acb0080d4b6caf9560ae295667eee6f8ecececd710d2043482ffb3186de3cd2b972d20dafcc2f0064142aa37a5ad5e8308c4dd3dde87e50a2cf7b2be60c0649bb7a8b50a3bb1a20e35f043fa8e65ab90cb7b0517210ffa3f6cf0c2714d1ddc9d9aa2710cfc7a6d03208f5e569998fcfa0c8599ab8e633619546c6793a232debddcae6847a20e2085a15a58dfe7879c32cea344f650382b568b773ecd696ce9a8bee6d971fe8545a4d8cbcec2ab8689fe33932ad7bdf68255775e06498d9f414a5494111b73997b5759824569dc7fd8fbc80f0ab6551bc0679690fd2dbfa6a76d5d17ddae2a5261b65c1dfe41eabee7124c11843f700d27d71316d39553edb793b70a73c1feb04ce2e920fc45214b187c1e6bc5c1814bb0b94ee8268cb326e60e7b00084ceb31c5a80cdae587d8fe5fdd1c22a8a493b7ae9ef22d09f2cc4282106a216134dd41ef89ab1b8174b82ff8ed9a288381d7e8248975cf5b12e97266e329c7752ea0e8eccad671dce399cd295b4462fd0866946c8e7bb75c6e2885a4ef62288737bff25a2c641948edf21115d3fbee53f1d6df6db7134c3517f93fc0f912fada2d2aa9df19496f881ed126bf22de27c41d3be11a4824be52c9efa4cc7157ef829b2e514c59e3b85639cf0a2c55c4e48c679eeb40f8d123edc138da02a75c82f3e9d06060b122fa23a3ddcc6cfa9229e2617b1d0d06e1be4f70389a210ddaa3fde718a3155bdb54b75cc0a9bfd939bf80260436c6f10296e273e2b9e8b8001b88a955ea6bc087007636269b9abdf075e9c71f291c3e3221d8c297b88d193e5a26fb1740b95af9f2ce3088bffac2f5aaf63370c1bcb77c3fafc7e7e0bc7a5d41de637536d87dc000d774af7f977a9688540ceb2068381eb9cd1bb2e51590534f66e7ba134bcbcddbdf62c2cf80c162f7c4ea57af6fe4fd83734d6161f77354a394125e37034ffb41c3ada3a48d15d4d97318b9fa67a98d930869fcf7aa39aabf4be7bda632d50253607ffdc7ba31c1a5dd48e9eb828ad8aa329e0d29118a402e0e2bdf460dc1926ffe4d3437133554d836c43c0a8170ba329157c31ebae1ba3c0e40c98180ffdc4dfd9435f607f972c909b324208193d8490ac26284e2f84fdba129b508eb818c36fe49d2181bce213c13917821ef3882e73c878e77a0f25792539f432c4987d4c02f35aa2b1cda09f8aba341809941dd804fc287ed59a477c610b883188cf2fdfd1c51f2fd3fbbda72fdc5257ae1d769bd71bc7048c899cc185de7bd849cfa732f3bf9b010e207f203dddcba1e855285233625e0e06676f68ef3e2acd77eb2dde1044f2f40e210d0ee1b1690710bbefdc2bddd78972eff559401c3e8dd095064cc61f10dd8e214e2d8a019d0686e9199c6fd79dd1928cf3cd8676e3f35221bec1b1c5a4d20b7b981e7508898cf682501446ebd9a542575b94ce7ca94d45f19d5ca7a426a4909da30092ab5716c4da1feee7e9a6990e1da86cb838fd392a25c1c3b6fa8e9a830f91b46805efc04eec66dee65642d0310a94ec194d5e8a6459f29e5fead9665387fce109f99cb687a461b2466045f47392a881903a051076ccbd37afdfe5a85a9d89e1e97fcc2279e54e6ffc7d66509fd0f5cb5af4b70fadcd584b1c86cc61b2b7d7565c11f32131291670167f79d6ef60b15f9598aa5a806dba706203a2e699740314ac47868628576308162f9eb930cf49b345865ca50eb1b3ca1abae9d776e19a313a9d2badd28fd907080bce17a671025ca2280fd754"
enc_flag = "16c63370ac3860ec7eb12f9ec357d462f8513ee887cd86481b521b2bd7995d8abecd595e2ef6fc554cb04d813848b19c06290f0818274303842e68fdc280f1fec612826f"
ct = bytes.fromhex(ct)
enc_flag = bytes.fromhex(enc_flag)

ct_bits = [int(b) for b in bin(int.from_bytes(ct, 'big'))[2:].zfill(8 * len(ct))]
print(ct_bits.count(1))

# check if yz_list.obj exists
if os.path.exists("./yz_list.obj.sobj"):
    yz_list = load("./yz_list.obj.sobj")
else:
    yz_list = []
    for i in tqdm(range(len(pt) * 8)):
        yz_list.append(cipher_sym.get_yz())
    save(yz_list, "./yz_list.obj")
    
def all_monomials(x1s, x2s):
    d1_monos = x1s[:] + x2s[:]
    d2_monos = []
    for xi in x1s:
        for xj in x2s:
            d2_monos.append(xi*xj)
    return [1] + d1_monos + d2_monos

def fast_coef_mat(monos, polys, br_ring):
    mono_to_index = {}
    for i, mono in enumerate(monos):
        mono_to_index[br_ring(mono)] = i
    # mat = matrix(GF(2), len(polys), len(monos))
    mat = [[0] * len(monos) for i in range(len(polys))]
    for i, f in tqdm(list(enumerate(polys))):
        for mono in f:
            # mat[i,mono_to_index[mono]] = 1
            mat[i][mono_to_index[mono]] = 1
    return mat

eqs = []
for i, bit in enumerate(ct_bits):
    if bit == 1:
        eqs.append(yz_list[i][0]*yz_list[i][1] + yz_list[i][0] + yz_list[i][1] + 1)
        

x2s = key_sym[256:384]
x1s = key_sym[128:256]
monos = all_monomials(list(x1s)[1:], list(x2s)[2:])
print(f"[+] total equations {len(eqs)}")
print(f"[+] total monomials {len(monos)}")
for v1 in [0]:
    for v2 in [0]:
        for v3 in [1]:
            new_eqs = []
            for eq in eqs:
                new_eqs.append(eq.subs({x1s[0]:v1, x2s[0]:v2, x2s[1]: v3}))
            mat = fast_coef_mat(monos, new_eqs, br512)
            mat = matrix(GF(2), mat)
            B = vector(GF(2),[mat[j,0] for j in range(len(eqs))])
            mat = mat[:, 1:]
            print(f"[+] {mat.dimensions() = }, {mat.rank() = }")
            try:
                sol = mat.solve_right(B)
                print(f"[+] solution found for x1[0] = {v1}, x2[0] = {v2}, x2[1] = {v3}")
                print(f"[+] solution: {sol}")
                ker = mat.right_kernel()
                for v in ker.basis():
                    print(f"[+] kernel vector: {v}")
                # break
            except:
                print(f"[+] no solution for x1[0] = {v1}, x2[0] = {v2}, x2[1] = {v3}")
                continue
