def randomPermutation(n):
    P = zero_matrix(n,n)

    I = list(range(n))
    shuffle(I)
    
    for i in range(n):
        P[i,I[i]] = 1
    
    return P

def randomMonomial(n,q):
    Fq = GF(q)
    P = randomPermutation(n).change_ring(Fq)
    D = identity_matrix(Fq,n)
    for i in range(n):
        d_i = 0
        while d_i == 0:
            d_i = Fq.random_element()
        D[i,i] *= d_i

    return P*D