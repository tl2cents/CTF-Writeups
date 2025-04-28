
## Writeup

[Tetration](https://en.wikipedia.org/wiki/Tetration) is something like:

$$
^na = \underbrace{a^{a^{\cdot a}}}_n
$$

The challenge will return the iterated exponentials with secret $`x`$:

$$
\exp _a^n(x)=a^{a^{a^{\cdot x}}} \text { with } n{-as.}
$$

For the case $n = 1$, it degenerates to normal discrete logarithm. However, the server samples its prime from a fixed prime set (see [server_primes_tester.py](./server_primes_tester.py)) and there are not so many smooth-order subgroups for us to recover the secret $`x`$.

Let's consider how to solve the super discrete logarithm with power times $`n = 2`$:

$$
\exp_{g}^{2}(x)= g^{g^x} \mod p.
$$

This can be rewritten as:

$$
g^{g^x} = g^{g^x \pmod {p - 1}} \mod p
$$ 

Actually, for the $`i`$-th power (from the lower), its modulo is $`\varphi^{i}(p)`$ where $`\varphi^{i}(p)`$ is the composition of $i$ Euler functions. If we choose a generator $`g`$ such that it is a small-order subgroup generator in $`\mathbb{Z}_{p - 1}`$, we can simply brute force the value of $`x \mod \textsf{ord}(g)`$ given that $`\exp_{g}^{2}(x) =  g^{g^x \pmod {p - 1}} \mod p`$. We find that some primes in the server has special form:

``` python
p = 670144747631070976739015819027954827310379693667090873445520193836663869580245599076670148076473491050020123654751096623483807617465722698994356143777563707
q = 954622147622608228972957007162328813832449706078477027700171216291543973761033616918333544268480756481510147656340593480746164697244619229336689663500803
assert p - 1 == 2 * 3**3 * 13 * q
assert q - 1 ==   2 * 3**320
```

For this prime, we are able to recover $`x \mod 3^{320}`$ by reconnecting to the server multiple times. Specifically, given knowledge of $`x \mod 3^{h}`$, we can recover $`x \mod 3^{h + \Delta}`$ in time approximately $`3^{\Delta}`$. For further details, please refer to [exp.py](./exp.py).