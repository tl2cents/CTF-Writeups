from pwn import remote, process, context
import time
import os
from sage.all import crt
# context.log_level = "debug"

# local = False
local = True

if local:
    io = process(["sage", "server.sage"], env={"HOME": os.environ["HOME"], "FLAG": "flag{0123qwert45}"}, stderr=process.STDOUT)
else:
    # 39.106.16.204:24045
    io = remote("39.106.16.204", 24045)

io.recvuntil("🌌 ".encode())
min_time = 1
max_time = 0
times = []
threshhold = 0.3
n_estimate = 50
for input_num in range(1, 2**10):
    st = time.time()
    io.sendlines([str(input_num).encode()] * n_estimate)
    io.recvuntil("🌌 ".encode() * n_estimate)
    et = time.time()
    # print(f"Time taken: {et - st} seconds")
    cost = et - st
    if cost < min_time:
        min_time = cost
        min_input = input_num
    if cost > max_time:
        max_time = cost
        max_input = input_num
    if cost > threshhold:
        print(f"Input {input_num} took too long: {cost} seconds")
    times.append(cost)

avg_time = sum(times) / len(times)
print(f"Average time: {avg_time} seconds")
print(f"Min time: {min_time} seconds for input {min_input}")
print(f"Max time: {max_time} seconds for input {max_input}")
io.close()