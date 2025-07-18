set_random_seed(1)

load("utils.sage")
load("cf.sage")

def testCF(n,k,q):

    Fq = GF(q)
    Ik = identity_matrix(Fq,k)

    A1 = random_matrix(Fq, k, n-k)
    Qr = randomMonomial(k,q)
    Qc = randomMonomial(n-k,q)
    A2 = Qr*A1*Qc

    G1 = Ik.augment(A1)
    G2 = Ik.augment(A2)
    
    try:
        C1, Qr1, Qc1 = CF(G1)
        C2, Qr2, Qc2 = CF(G2)
    except CFException:
        return False


    A1_ = C1.submatrix(0,k,k,n-k)
    A2_ = C2.submatrix(0,k,k,n-k)
    assert A1_ == Qr1 * A1 * Qc1
    assert A2_ == Qr2 * A2 * Qc2
    assert C1==C2
    
    return True

trials = 50
nRange = range(50,110,10)
rRange = range(1,6)
Q = [2,3,4,5,7,8,9,11,13]

print("Determining success rate of canonical form function.")

for q in Q:
    print("\nq = %d\n" % q)
    print("n:\t\t",end="")
    for n in nRange:
        print("%d\t" % n, end="")
    print("")

    for r in rRange:
        r /= 10
        print("k/n = %.1f" % r, end="\t")

        for n in nRange:

            k = floor(r*n)

            succRate = 0
            
            for _ in range(trials):
                if testCF(n,k,q):
                    succRate += 1
            succRate /= trials

            print("%.2f\t" % succRate, end="", flush=True)
        print("")
    print("")