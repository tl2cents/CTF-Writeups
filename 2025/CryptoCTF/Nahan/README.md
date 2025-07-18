
## Writeup

> Solved by [Threonine](https://github.com/Threonine), [deebato](https://github.com/D33BaT0) and me.

This problem turns to the following system of equations:

``` python
import random
s = random.randint(0, 2**256 - 1)  
r = [random.randint(0, 2**256 - 1) for _ in range(128)] 
w = [int(s ^ r[i]).bit_count() for i in range(128)]
# given r, w , recover s
```

If you feed it to LLM like ChatGPT/Gemini/Claude, it will give you a correct solution, see [gpt_solve1.py](./gpt_solve1.py).


> By the way, we wasted a lot of time on this problem because we were all on the wrong track: Ax = b in integer ring, then LLL and find binary solutions.