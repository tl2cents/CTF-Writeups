import itertools
    
gens = [3, 5, 7, 11, 13, 17]
exp_bound = 6

target_sub_group = sorted(range(1, 4096 * 2, 2))
sums = {}
sums[1] = 0
sub_group = {}
sub_group[1] = [0] * len(gens)
exps = itertools.product(range(exp_bound), repeat=len(gens))

for exp in exps:
    s = 1
    for g, e in zip(gens, exp):
        s = s * g ** e % (4096 * 2)
    if s not in sub_group:
        sub_group[s] = exp
        sums[s] = sum(exp)
    elif sum(exp) < sums[s]:
        sub_group[s] = exp
        sums[s] = sum(exp)
                        
# print(f"{len(sub_group) = }")
sub_group_keys = sorted(sub_group.keys())
assert (sub_group_keys == target_sub_group)