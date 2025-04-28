
## Writeup

I did not figure out the exact algebraic structure of the curve. nvm, I just brute-forced the order in candidates like `p^k+1`, `p^k-1` and `p^k` and this works well for all prime factors of `n` in this challenge. Then solve the dlogs in the smooth subgroups of $`\mathbf{E}(\mathbb{F}_{p})`$.


## Customizable Dlog

Sage (version 10.3) provides great customizable discrete log computation in `discrete_log`. An example in this challenge:

``` python
discrete_log(qs[idx], gs[idx], os[idx], operation = "other", op = lambda x, y: point_addition(x, y, mods[idx]), identity=O, inverse= lambda x: inverse_point(x, mods[idx], os[idx]), algorithm="rho")
```

The parameters should be well-defined. Refer to [exp.py](./exp.py) for details.