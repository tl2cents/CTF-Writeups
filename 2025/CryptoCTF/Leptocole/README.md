
## Writeup

> Solved by me and [deebato](https://github.com/D33BaT0).

This problem is called "Linear Equivalence Problem" in the literature. See [eprint/2020/801](https://eprint.iacr.org/2020/801.pdf) for more details. We can estimate the complexity of the problem in [Linear Equivalence Estimator](https://estimators.crypto.tii.ae/configuration?id=LEEstimator). For this challenge, the complexity is around $2^{22}$, which is feasible.

Actually, I found two implementations for solving LEP:

- lep-cf: https://github.com/juliannowakowski/lep-cf/tree/main
- LESS: https://github.com/paolo-santini/LESS_project/tree/main

The first one perfectly solves this challenge with only minor modifications.

