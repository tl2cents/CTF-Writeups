# 模拟 server，给定真实 x，接受两个查询值 y1, y2 返回 f(x,y1)==f(x,y2) 的布尔结果
def server(x):
    # 返回查询函数
    def query(y1, y2):
        return abs(x ^ y1) == abs(x ^ y2)
    return query

# 利用上述 Oracle 查询逐位恢复 x 的函数
def recover_x(query_func, max_bits=64):
    """
    query_func: 用于比较 |x^y1| == |x^y2| 的函数，由 server(x) 提供
    max_bits:   最大比特位数限制（为了程序终止，可根据需要设置）
    """
    recovered = 0  # 当前已恢复的低位部分 r
    for i in range(max_bits):
        # 构造查询 y1 = r + 2^i, y2 = r - 2^i
        y1 = recovered + (1 << i)
        y2 = recovered - (1 << i)
        # 调用查询
        equal = query_func(y1, y2)
        # 如果返回 False，说明第 i 位为 1；否则为 0
        if not equal:
            recovered |= (1 << i)  # 将第 i 位置为 1
    return recovered

# 示例：生成随机 x，测试恢复结果
import random
x_true = random.getrandbits(256)  # 随机 20 位正整数
query = server(x_true)
x_rec = recover_x(query, max_bits=256)
print(f"真实 x = {x_true}, 恢复 x = {x_rec}, 匹配 = {x_true == x_rec}")