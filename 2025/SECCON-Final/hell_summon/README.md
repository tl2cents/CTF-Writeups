
## Writeup

Given the following equations:

$$
r \cdot (H \oplus M_i) = \underbrace{T_h \cdot 2^16 + T_{l}}_{T_i} \mod N
$$

where $M_i$ and the high 32 bits of $T_i$, i.e., $T_h$ are known. This is a typical HNP-SUM problem.