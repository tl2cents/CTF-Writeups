# jqctf 2025 r4nd0m

This challenge source code is short:

``` python
import os, random
flag = os.getenv("FLAG", "flag{redacted}")

def encrypt(key, message):
    otp = random.Random(key).randbytes(len(message))
    return bytes([i ^ j for i, j in zip(otp, message)])

while True:
    key = int.from_bytes(flag.encode(), 'big')
    msg = bytes.fromhex(input('💬'))[:64]
    err = int(input('🔧'))
    print('🔒', encrypt(key ^ err, msg).hex())
```



## Mersenne Twister Seeding 

The seeding in python's random starts here [randommodule.c](https://github.com/python/cpython/blob/feac343d1aeef9edce91640e4bbc74516980db9a/Modules/_randommodule.c#L294). For seed with `int` type, it converts the integer seed $s$  into an array of 32-bit integers and feed it into [init_by_array](https://github.com/python/cpython/blob/feac343d1aeef9edce91640e4bbc74516980db9a/Modules/_randommodule.c#L219). However, the core process of `init_by_array` has a non-linear ARX-like structure.  We can recover the seed given accurate 32-bit integers of the 624×32-bit seeding state. The server does not provide enough output bits to recover the full 19937-bit state after seeding. Actually, we will not learn any accurate 32-bit integer given only 64 bytes output. A possible way to use the known error is to build many (high-degree multivariate) equations and choose special errors to retrieve linear (or low-degree) equations. It seems Z3 is not powerful enough to handle this case and one may use [msolve](https://github.com/algebraic-solving/msolve) for solving the multivariate equations.



The author's hint led me to find some suspicious operations before the seeding:

``` c
    /* This algorithm relies on the number being unsigned.
     * So: if the arg is a PyLong, use its absolute value.
     * Otherwise use its hash value, cast to unsigned.
     */
    if (PyLong_CheckExact(arg)) {
        n = PyNumber_Absolute(arg);
    } else if (PyLong_Check(arg)) {
        /* Calling int.__abs__() prevents calling arg.__abs__(), which might
           return an invalid value. See issue #31478. */
        _randomstate *state = _randomstate_type(Py_TYPE(self));
        n = PyObject_CallOneArg(state->Long___abs__, arg);
    }
```



**The seed was converted to its absolute value before use, and the server did not filter out negative values.** Now, we focus on the negative integer and its XOR in python. We can construct an oracle of `f(y1,y2) = abs(x^y1) == abs(x^y2)`  by sending `y1, y2` to the server and compare their key stream to leak `f(y1, y2)`. Such an oracle can actually leak every bit of $x$ by two queries.



## Integer in Python

In Python, the `int` type is a signed, unlimited-width integer. In the following, we assume the signed bit $s$ and its length $\ell$ are stored separately. For any integer $(-1)^{s} x$ in python, the stored bits are actually its complement bits:

$$
b_{x} = 
\begin{cases}
x, & \text{ if } s = 0 \\
2^{\ell} - x  & \text{ if } s = 1
\end{cases}
$$

For the negative int, there are infinite 1s following if we extend it to infinite width (0s for the positive int). We can now clarify some non-obvious properties of XOR operations when applied to negative integers. In python, we can see that:

``` python
>>> 3^4
7
>>> -3^-4
1
>>> -3^4
-7
>>> 3^-4
-1
```

The XOR operation is applied bitwise to the two’s complement representations, including the sign bit, and the resulting bits are then interpreted as a value in complement form. For the case `-3^4`,  their binary bits are `101` and `100` and the resulting XORed bits `001` with signed bit $s = 1 \oplus 0 = 1$ and length $\ell = 3$  represents $(-1) \cdot (2^3 - 1) = -7$. This is consistent with the result and the readers can validate other cases, too. 

When taking the absolute value of a number, negating a negative integer involves more than simply flipping the sign bit. **What are the underlying bitwise operations when a value is negated?** One can easily verify that the following identity holds in python:

``` python
-x === ~x + 1
```

If we bitwise NOT the bits of a positive value $x$, we have $x + \not x = 2^{\ell} - 1$. Since the singed bit is also flipped to 1, we know the actual value of `~x` is $(-1)(2^{\ell} - \not x) = -x - 1$ which exactly leads to the identity `-x === ~x + 1`.



## Lifting +1 to Any Bit

It's oblivious that if the lsb of $x$ is $0$, then `abs(x^(-1)) == abs(x^1)` is true (otherwise false). We now turn to a more general case: assuming that the $(i-1)$ lsb bits of $x$ are recovered as $r = x \pmod{2^{i}}$,  how can we determine the $i$-th bit of $x$ by the oracle `f(y1,y2) = abs(x^y1) == abs(x^y2)`?  

We first figure out what negative number $y$ to submit where the server computes `abs(x^y) = ~(x^y) +  1`. We intend to propagate the the `+1` operation to the i-th bit position. Make the $i-1$ lsb bits of `~(x^y)` be $\underbrace{11\ldots1}_{i - 1}$ and the `+1` will propagate to the $i$-th bit. The complement bits of $y$ should be exactly $r$ but with negative signed bit. Therefore, we need to submit $y = (-1) (2^i - r) = r - 2^i$.  We note that the msb bits ($\ge i$) of $x$ are NOTed twice:

1. XOR with complement bits of y (all 1s): `x^y`
2. Not the result in `abs`: `~(x^y)`.

This ultimately preserve the original value. Only the final `+1` carry propagation affects the value of the i-th bit. If the $i$-th bit is 0, the final result satisfies: `~(x^(r − 2**i) + 1 = x^(r + 2**i)`. This gives us a distinguisher:

- If `f(r - 2**i, r + 2**i)` returns true,  the $i$-th bit of $x$ is 0.
- If `f(r - 2**i, r + 2**i)` returns false,  the $i$-th bit of $x$ is 1.

We can recover the bits of $x$ from lsb recursively. The following demo simulates the distinguisher:

``` python
import random
def server(x):
    def query(y1, y2):
        return abs(x ^ y1) == abs(x ^ y2)
    return query


def recover_x(query_func, max_bits=64):
    """
    query_func: return |x^y1| == |x^y2|
    max_bits: maximum bits of secret x
    """
    recovered = 0  # the recovered lsb r
    for i in range(max_bits):
        # query y1 = r + 2^i, y2 = r - 2^i
        y1 = recovered + (1 << i)
        y2 = recovered - (1 << i)

        equal = query_func(y1, y2)
        # If False，i-th bit is 1；otherwise 0
        if not equal:
            recovered |= (1 << i) 
    return recovered

x_true = random.getrandbits(256)
query = server(x_true)
x_rec = recover_x(query, max_bits=256)
print(f"real x = {x_true}, recovered x = {x_rec}, match = {x_true == x_rec}")
```

>
> BTW, the above code can be generated by ChatGPT-4o by proper prompting.
>































