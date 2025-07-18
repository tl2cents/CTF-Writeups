load("cf.sage")

def permuteSetToFront(G, J):
    G_T = G.transpose()
    I = list(range(G.ncols()))

    G_J = []
    G_J_complement = []
    for j in J:
        G_J.append(G_T[j])
    for j in list(set(I) - set(J)):
        G_J_complement.append(G_T[j])

    G_J = matrix(G_J).transpose()
    G_J_complement = matrix(G_J_complement).transpose()

    return G_J.augment(G_J_complement)

def projectOntoSet(G, J):
    k = G.nrows()
    l = len(J)
    G = permuteSetToFront(G, J)
    return G.submatrix(0,0,k,l)

def isSystematic(G):
    k = G.nrows()
    Fq = G.base_ring()
    Ik = identity_matrix(GF(q),k)

    return G.submatrix(0,0,k,k) == Ik

def recoverMon(G1,G2,J1,J2):
    k = G1.nrows()
    n = G1.ncols()
    Fq = G1.base_ring()

    assert k == G2.nrows()
    assert n == G2.ncols()
    assert Fq == G2.base_ring()
    assert len(J1) == k
    assert len(J2) == k

    In = identity_matrix(Fq, n)

    G1_ = permuteSetToFront(G1, J1).echelon_form()
    G2_ = permuteSetToFront(G2, J2).echelon_form()

    _, Qr1, Qc1 = CF(G1_)
    _, Qr2, Qc2 = CF(G2_)

    U = projectOntoSet(G2,J2) * Qr2.inverse() * Qr1 * projectOntoSet(G1,J1).inverse()

    P = block_matrix([
        [Qr1.inverse() * Qr2, zero_matrix(Fq,k,n-k)],
        [zero_matrix(Fq,n-k,k), Qc1*Qc2.inverse()],
    ])

    P = permuteSetToFront(In,J1) * P * permuteSetToFront(In,J2).transpose()

    return U, P

def lepCollSearch(G1, G2):

    k = G1.nrows()
    n = G1.ncols()

    assert k == G2.nrows()
    assert n == G2.ncols()
    
    T = floor( sqrt( 1/2 * binomial(n,k) ) )
    rangeN = list(range(n))

    L = {}

    for _ in range(T):
        J1 = sample(rangeN, k)
        G1_ = permuteSetToFront(G1, J1).echelon_form()

        if isSystematic(G1_):
            try:
                C1,_,_ = CF(G1_)
            except CFException:
                continue
            
            L[str(C1)] = J1
    
    for _ in range(T):
        J2 = sample(rangeN, k)
        G2_ = permuteSetToFront(G2, J2).echelon_form()

        if isSystematic(G2_):
            try:
                C2,_,_ = CF(G2_)
            except CFException:
                continue
            
            C2 = str(C2)
            if C2 in L:
                J1 = L[C2] 
                return recoverMon(G1,G2,J1,J2)    