from ortools.sat.python import cp_model
import random
s = random.randint(0, 2**256 - 1)  # 假设s是一个256位的整数
r = [random.randint(0, 2**256 - 1) for _ in range(128)]  # 假设r是一个包含128个256位整数的列表
w = [int(s ^ r[i]).bit_count() for i in range(128)]  # 已知的w_i

print("s =", hex(s))

model = cp_model.CpModel()
# 256 个 0/1 变量
b = [model.NewBoolVar(f"b[{j}]") for j in range(256)]

for i, (r_i, w_i) in enumerate(zip(r, w)):
    # 对第 i 个观测，先构造一组 BoolVar x_ij = b_j XOR r_ij
    x = []
    for j in range(256):
        bit = (r_i >> j) & 1
        if bit == 0:
            # x_ij == b_j
            x.append(b[j])
        else:
            # x_ij == NOT b_j
            xj = model.NewBoolVar(f"x[{i},{j}]")
            model.Add(xj + b[j] == 1)
            x.append(xj)
    # 卡丁纳尔性约束：sum_j x[j] == w_i
    model.Add(sum(x) == w_i)

solver = cp_model.CpSolver()
status = solver.Solve(model)
if status == cp_model.OPTIMAL or status == cp_model.FEASIBLE:
    s = 0
    for j in range(256):
        if solver.Value(b[j]):
            s |= (1 << j)
    print("s =", hex(s))
else:
    print("无解")
