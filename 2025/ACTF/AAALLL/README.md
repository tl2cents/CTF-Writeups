
## Writeup

We need to recover a polynomial $`f(x) = \sum_{i=0}^{n-1} a_i x^i`$ over $`\mathbb{F}_{p}`$ with its coefficients $`a_i`$ in $`[-1, 0, 1]`$. Given only $`t = \lfloor \frac{n}{2} \rfloor`$ evaluations of $`(x_i, y_i=f(x_{i}))`$ where $x_i^n  + 1 \equiv 0 \pmod{p}`$, we can recover the coefficients of $`f(x)`$ using LLL since the solution coefficients are small (ternary).

My first trial is based on the following lattice construction (see [exp1.py](./exp1.py)):

$$
\begin{bmatrix}
    x_1^0 & x_2^0 & \cdots & x_{t}^{0} & 1 & \\
    x_1^1 & x_2^1 & \cdots & x_{t}^{1} & & 1 \\
    \vdots & \vdots & \ddots & \vdots & & &\ddots \\
    x_1^{n-1} & x_2^{n-1} & \cdots & x_{t}^{n-1} & & & & 1 \\
    y_1 & y_2 & \cdots & y_{t} & & & & &1 \\
    p &  &  &  \\
     & p &  &  \\
     & & \ddots &  \\
     &  & & p \\
\end{bmatrix}_{(n + t + 1) \times (n + t + 1)}
$$

For this challenge, the dimension is $n + t + 1 = 676$. I used `flatter` but it took too long. Then I turned to the kernel space since the first $`t`$ dimensions of our target vector in above lattice are forced to be $`0`$ (this is exactly a SIS problem). Let $`M`$ of size $`n \times t`$ be the vandermonde matrix spanned by $`x_i`$ and $v_0$ be a solution of $`Mx = (y_1, \ldots, y_t)`$. We can do lattice reduction on matrix $`L = \mathcal{ker}(M) || v_0`$ of size $(n - t) \times n$ modulo $`p`$. This only involves doing LLL on a $`n \times n`$ matrix for $`n = 450`$ and solves the challenge within 2 minutes (see [exp2.py](./exp2.py)).


