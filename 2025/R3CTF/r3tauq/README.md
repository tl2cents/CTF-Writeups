
## Writeup

I solved this challenge but some quaternion algebra but I am still unclear about the proofs of some conclusions on quaternion algebraic groups. I will directly use the conclusions that I found by guessing and testing in sagemath.

## Quaternion Algebra

A quaternion algebra is a four-dimensional algebra over a ring. For `QuaternionAlgebra(R, u, v)` where `R` is a ring and `u`, `v` are elements of `R`, the quaternion algebra for a quaternion $a + bi + cj + dj$ is defined by the relations:
- `i^2 = u`
- `j^2 = v`
- `ij = -ji`
- `k = ij`

**The multiplication is not commutative on quaternion algebraic groups!** Let $`R = \mathbb{F}_p`$. This challenge involves two properties of quaternion algebraic groups:
1. **Property 1. Power Formula**. The power formula of $`(a_0 + b_0 i + c_0 j + d_0 k)^n = a_n + b_n i + c_n j + d_n k`$ can be simplified as follows:
    
    $$
    \begin{cases}
    b_n = X b_0\\
    c_n = X c_0\\
    d_n = Y d_0
    \end{cases}
    $$
    
    For more details, see the [SECCON RSA 4.0](https://7rocky.github.io/en/ctf/other/seccon-ctf/rsa-4.0/) and [New Formula for Computing Quaternion Powers](https://www.scirp.org/pdf/am_2022033014505665.pdf).
2. **Property 2. Group Homomorphism to $\mathbb{F}_p$**. We define the square abs mapping as:
    
    $$
    \textsf{abs}(a + bi + cj + dk) = a^2 - u b^2 - v c^2 + uvd^2 \mod p
    $$
    
    which is a group homomorphism from the quaternion algebra to $\mathbb{F}_p$. This means:
    
    $$
    \textsf{abs}(q_1 \cdot q_2) = \textsf{abs}(q_1) \cdot \textsf{abs}(q_2) \mod p
    $$
    
    and implies that:
    
    $$
    \textsf{abs}\left(q^n \right) = \textsf{abs}(q)^n \mod p
    $$


> Some useful links for quaternion algebra in ctf: [SECCON 2023 Final: DLP 4.0, KEX 4.0](https://qiita.com/saitenntaisei/items/5f9caa9110fe38edbc82) and [IRISCTF 2025 knutsacque](https://blog.whale-tw.com/2025/01/06/irisctf-2025/#knutsacque).

## Solution

```python
p, q, r, x, y = [getPrime(256) for _ in range(3)] + [getPrime(256) << 128 for _ in range(2)]
secret = "".join([choice(string.ascii_letters) for _ in range(77)])
PR.<i, j, k> = QuaternionAlgebra(Zmod(p*q), -x, -y)
print("🎁 :", [p*q] + list(PR([x+y, p+x, q+y, r])^bytes_to_long(777*secret.encode())) + [AES.new(key=md5(secret.encode()).digest(), nonce=b"Tiffany", mode=AES.MODE_CTR).encrypt(flag).hex()])
```

The challenge only gives us:

$$
(a, b, c, d) = [x+y, p + x, q + y, r]^{s}
$$

in `QuaternionAlgebra(Zmod(p*q), -x, -y)`.

### Recover $(p, q, x, y)$

By property 1:

$$
\begin{cases}
b = X(p + x) \mod n \\
c = X(q + y) \mod n \\
d = Xr \mod n
\end{cases}
$$

where $`p + x \le 2^{384}$, $q + y \le 2^{384}`$, and $`r \le 2^{256}`$ are all far less than $`n \approx 2^{512}`$. We can recover them by LLL to find the shortest vector in the lattice:

$$
\mathcal{L} = 
\begin{bmatrix}
b & c & d \cdot 2^{128} \\
n & 0 & 0 \\
0 & n & 0 \\
0 & 0 & n \cdot 2^{128}
\end{bmatrix}.
$$

since $`\mathcal{L}`$ contains our target short vector $`t = (p + x, q + y, r \cdot 2^{128})`$. Note that $`p + x \equiv p \mod 2^{128}`$ and $`q + y \equiv q \mod 2^{128}`$ leaks half lsbs of $`p, q`$, we can brutefore 8 bits more to recover $`p, q`$ by coppersmith's method. 

See [exp.py](./exp.py) for details.


## Recover $s \mod \phi(n)$

By property 2, we can degenerate the discrete logarithm of the quaternion algebra to the discrete logarithm of $`\mathbb{F}_p$ and $\mathbb{F}_q`$

$$
\begin{cases}
\textsf{abs}\left([a, b, c, d] \right) = \textsf{abs}\left([x+y, p+x, q+y, r]\right) ^{s} \mod p  \\
\textsf{abs}\left([a, b, c, d]\right) = \textsf{abs}\left([x+y, p+x, q+y, r]\right) ^{s} \mod q
\end{cases}
$$

In this case, we have

``` bash
sage: factor(p-1)
2^4 * 5 * 6359 * 78030424691 * 2295202126216837008978652626989273467723189905747503092156937
sage: factor(q-1)
2^2 * 151 * 761 * 172264199 * 1272395036149799262058207121218496577799325253210771211721273551
```

The 200-bit prime factor requires some sub-exponential algorithms to solve the discrete logarithm problem. I used [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs) to solve the discrete logarithm in subgroups of large prime orders. For example, in the case of $q$, we can run the following command:

```bash
$ cado-nfs.py -dlp -ell 1272395036149799262058207121218496577799325253210771211721273551 target=30276072848139170007083404041300769699307841465505983042645514710610334966369 100748500420633602436909572573651942923829948109715215298913760623104145908957 -t 12
...
Info:Complete Factorization / Discrete logarithm: Total cpu/elapsed time for entire Discrete logarithm: 658.74/137.706
Info:root: CADO_DEBUG is on, data kept in /tmp/cado.5b74sbj8
Info:root: If you want to compute one or several new target(s), run cado-nfs.py /tmp/cado.5b74sbj8/p80.parameters_snapshot.0 target=<target>[,<target>,...]
Info:root: logbase = 85957352019927071818355242680681650991272249836607379548748536511737186451317
Info:root: target = 30276072848139170007083404041300769699307841465505983042645514710610334966369
Info:root: log(target) = 627742443601599637721620943837620376253619043926690819089673200 mod ell
627742443601599637721620943837620376253619043926690819089673200

$ cado-nfs.py /tmp/cado.5b74sbj8/p80.parameters_snapshot.0 target=45926341433646374742377904547321445206388188844141136065098557452004567800661
Info:root: logbase = 85957352019927071818355242680681650991272249836607379548748536511737186451317
Info:root: target = 45926341433646374742377904547321445206388188844141136065098557452004567800661
Info:root: log(target) = 612201028157767105161030643594390845684422954246888494963653401 mod ell
612201028157767105161030643594390845684422954246888494963653401
```

This enables us to compute $`\log_g (y) = \frac{\log_{b} y}{\log_{b} g}`$. Denote

$$
\begin{cases}
g_p = \textsf{abs}\left([x+y, p+x, q+y, r]\right) \mod p \\
g_q = \textsf{abs}\left([x+y, p+x, q+y, r]\right) \mod q \\
y_p = \textsf{abs}\left([a, b, c, d]\right) \mod p \\
y_q = \textsf{abs}\left([a, b, c, d]\right) \mod q \\
\end{cases}
$$

Let $`m =\textsf{lcm}(\textsf{ord}(g_p), \textsf{ord}(g_q))`$. Then we can recover $`s \mod m`$ by solving $`\log_{g_p} y_p$ and $\log_{g_q} y_q`$.

## Recover the secret

We have recovered $`s_0 \equiv s \mod m`$ so far where $`m`$ is 508 bits while $`s = x\sum_{i=0}^{777} 2^{616i}`$ has a 616-bit unknown value $`x`$. Nevertheless, we can recover $`x`$ since it consists of 77 ascii letters. Again, we can apply LLL to find our target solution. We can compute $`x_0 \mod m`$ from

$$
x_0 = s_0 \cdot (\sum_{i=0}^{777} 2^{616i})^{-1} \mod m
$$

Then build the following lattice (93 is the middle value of ascii letters):

$$
\mathcal{L} = 
\begin{bmatrix}
2^{8 \cdot 0} & 1 \\
2^{8 \cdot 1} & & 1 \\
\vdots & & & \ddots \\
2^{8 \cdot 77} & & & & 1 \\
-x_0 & -93 & -93 & \cdots & -93 & 1 \\
m
\end{bmatrix}.
$$

We can rescale the first column by a large constant $c$ and use BKZ to find short enough vector to reconstruct the valid secret string. See [dlp.py](./dlp.py) for details.
