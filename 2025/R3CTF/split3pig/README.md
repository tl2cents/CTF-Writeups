
## Writeup

RSA modulus : $n = p \cdot q^2$. Given $e_1 \mid (p - 1)$ and $e_2 \mid (q - 1)$, the target is to factor $n$.

``` bash
sage: E1.bit_length()
244
sage: E2.bit_length()
243
sage: N.bit_length()
2607
```

We can recover $q \pmod {e_1 \cdot e_2}$ by:

$$
\begin{cases}
q^2 \equiv n \mod e_1 \\
q \equiv 1 \mod e_2
\end{cases}
$$

This will generates $2^5$ possible values for $r_q \equiv q \pmod {e_1 \cdot e_2}$. I guess the bitsize of $p, q$ is the same (actually this is not the case). Denote $q = k e_1 e_2 + r_q$ where $k$ is bounded by $K = 2^{qbit - 487}$ ($2^{382}$ for $qbit = \frac{2607}{3} = 869$). The coppersmith-bound is $N^{\frac{(2/3)^2}{2}} \approx 2^{579} \gg K$. Finally, adjust the unknown parameters (beta, K) to get the correct factorization. My final solution script used:

``` python
qbit = 870
K = 2**(qbit - e1_bit - e2_bit)
f = (x * E1*E2 + ZZ(rq))**2
roots = f.monic().small_roots(X= K, epsilon = 0.05, beta = 2/3 - 0.1)
```

## Remarks

From paper [Improved Results on Factoring General RSA Moduli with Known Bits](https://eprint.iacr.org/2018/609.pdf):

> Finally, we derive a unifying condition for factoring general RSA moduli $N=p^r q^s$ with known bits. For example, we roughly give the applicable ranges of $s$ for a fixed $r<10$ as follows since coprime integers $r, s \ll \log p$.
> - If $0.7 r<s<r$, we choose to solve $P Q+x=0(\bmod p q)$.
> - If $0.5 r<s \leq 0.7 r$, we choose to solve $(P+x)^r(Q+y)^s-N=0$.
> - Else cases, we choose to solve $P+x=0(\bmod p)$.
>

This challenge is the third case. Actually I tried [cuso](https://github.com/keeganryan/cuso) to solve this challenge fully automatically, but it failed (always killed or not able to find the roots).

> The author's intended solution is based on paper [New Results on the $\phi$-Hiding Assumption and Factoring Related RSA Moduli](https://www.iacr.org/cryptodb/data/paper.php?pubkey=35600).