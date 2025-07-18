

## Writeup

The signing process is weird:

$$
s \cdot (id + f) = (hm + r*sk)
$$

where $sk$ is the secret key, $f$ is a fixed value (half of the flag), $hm$ is the hash of the message, $id$ is our submitted `sign_id` and $r = [(id + f)G].x$.

The server only allows us to submit 3 different `sign_id`s. Let the ids be fixed, i.e., $0$, $-1$, and $1$, the corresponding $r$ values will be $r_0$, $r_1$, and $r_2$ respectively. **Then, each time we connect to the server, the only thing new in the server is the private key $sk_i$ while we can still get 3 equations.** Collect enough equations, i.e., the number of unknowns is less than the number of equations, we can solve for the multivariate equation system. See [exp_half_flag.py](./exp_half_flag.py) and [solve_local.py](./solve_local.py) for details.