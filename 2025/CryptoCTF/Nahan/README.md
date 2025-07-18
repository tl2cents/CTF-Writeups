
## Writeup

> Solved by [Threonine](https://github.com/Threonine), [deebato](https://github.com/D33BaT0) and me.

This challenge can be transformed into solving the following system of equations:

``` python
import random
s = random.randint(0, 2**256 - 1)  
r = [random.randint(0, 2**256 - 1) for _ in range(128)] 
w = [int(s ^ r[i]).bit_count() for i in range(128)]
# given r, w , recover s
```

If you feed it to an LLM like ChatGPT, Gemini, or Claude, it will return a correct solution. See [gpt_solve1.py](./gpt_solve1.py).


> By the way, we ended up wasting quite a bit of time on this problem because we were all heading in the wrong direction. We approached it as solving $Ax=b$ over the integers, then applying LLL to find binary solutions. However, the lattice approach didn’t work in this case because the basis matrix was poorly structured.
