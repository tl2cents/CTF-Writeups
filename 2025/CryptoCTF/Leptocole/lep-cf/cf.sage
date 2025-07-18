class CFException(Exception):
    pass

def sortWithPerm(L):
    L = [ (L[i],i) for i in range(len(L)) ]
    L = sorted(L)
    return zip(*L)

def moveRowsToBack(A, rows):
    if len(rows) > 0:
        bottomPart = matrix( A[i] for i in rows )
        A = A.delete_rows(rows)
        A = A.stack(bottomPart)
    return A

def moveColsToRight(A, cols):
    A = A.transpose()
    A = moveRowsToBack(A, cols)
    return A.transpose()

def permuteRows(A, permutation):
    return matrix( [ A[i] for i in permutation ] )

def permuteCols(A, permutation):
    A = A.transpose()
    A = permuteRows(A, permutation)
    return A.transpose()

def sortRows(A, minRow, maxRow, w):

    k = A.nrows()

    if maxRow > minRow:
        A_top = A[:minRow]
        A_mid = A[minRow:maxRow]
        A_bottom = A[maxRow:]

        signatures = []
        for a in A_mid:
            sig = sorted( [ a_i for a_i in a[:w] ] )
            if sig in signatures:
                raise CFException("Sorting failed.")
            
            signatures.append(sig)
        
        _, permutation = sortWithPerm(signatures)

        permutedMid = permuteRows(A_mid, permutation)

        A = A_top.stack( permutedMid ).stack( A_bottom )
        permutation = list(range(minRow)) + [ minRow+i for i in permutation ] + list(range(maxRow,k))

    else:
        permutation = list(range(k))

    return A, permutation

def sortCols(A, minCol, maxCol, h):
    A = A.transpose()
    A, permutation = sortRows(A, minCol, maxCol, h)
    return A.transpose(), permutation

def step1(A, row, Qr, Qc):
    A.swap_rows(0,row)
    Qr.swap_rows(0,row)

    J = []
    for i in range(A.ncols()):
        if A[0,i]!=0:
            c = A[0,i]^(-1)
            A.rescale_col(i, c)
            Qc.rescale_col(i, c)
        else:
            J.append(i)

    A = moveColsToRight(A,J)
    Qc = moveColsToRight(Qc,J)
    
    w = A.ncols() - len(J)

    return A, w, Qr, Qc

def step2(A, w, Qr):
    I = []
    for i in range(1,A.nrows()):
        s = sum( a_j for a_j in A[i][:w] )
        if s!=0:
            A.rescale_row( i, 1/s )
            Qr.rescale_row( i, 1/s )
        else:
            I.append(i)
    A = moveRowsToBack(A,I)
    Qr = moveRowsToBack(Qr,I)

    h = A.nrows() - len(I)

    return A, h, Qr

def step3(A, w, h, Qr, Qc):
    A, permutation = sortRows(A,1,h,w)
    Qr = permuteRows(Qr,permutation)
    A, permutation = sortCols(A,0,w,h)
    Qc = permuteCols(Qc,permutation)

    return A, Qr, Qc

def step4(A, w, h, Qr, Qc):
    A, Qc = updateRightScaling(A,h,w,Qc)
    A, Qr = updateLeftScaling(A,A.ncols(),h,Qr)

    A, permutation = sortRows(A,h,A.nrows(),w)
    Qr = permuteRows(Qr,permutation)
    
    A, permutation = sortCols(A,w,A.ncols(),h)
    Qc = permuteCols(Qc,permutation)

    return A, Qr, Qc

def updateRightScaling(A, maxRow, minCol, Qc):
    untouchedColumns = list( range(minCol,A.ncols()) )
    
    i = 0
    while i < maxRow and len(untouchedColumns) > 0:
        
        newlyTouched = []

        for j in untouchedColumns:
            if A[i,j]!=0:
                c = A[i,j]^(-1)
                A.rescale_col(j, c)
                Qc.rescale_col(j, c)
                newlyTouched.append(j)

        for j in newlyTouched:
            untouchedColumns.remove(j)
        
        i += 1
    
    if i==maxRow and len(untouchedColumns) > 0:
        raise CFException("Updating scaling failed.")
    
    return A, Qc

def updateLeftScaling(A, maxCol, minRow,Qr):
    A = A.transpose()
    Qr = Qr.transpose()
    A,Qr = updateRightScaling(A,maxCol,minRow,Qr)
    return A.transpose(), Qr.transpose()

def CF(G):

    k = G.nrows()
    n = G.ncols()
    Fq = G.base_ring()

    A_input = G.submatrix(0,k,k,n-k)

    L = []
    L_Qr = []
    L_Qc = []

    for i in range(k):
        A = copy(A_input)

        Qr = identity_matrix(Fq, k)
        Qc = identity_matrix(Fq, n-k)

        A, w, Qr, Qc = step1(A,i,Qr,Qc)
        A, h, Qr = step2(A,w,Qr)

        try:
            A, Qr, Qc = step3(A,w,h,Qr,Qc)
            A, Qr, Qc = step4(A,w,h,Qr,Qc)

            L.append(A)
            L_Qr.append(Qr)
            L_Qc.append(Qc)
        except CFException:
            pass
    
    if len(L) > 0:
        L, permutation = sortWithPerm(L)
        A = L[0]
        Qr = L_Qr[permutation[0]]
        Qc = L_Qc[permutation[0]]
        I = identity_matrix(Fq,k)
        return I.augment(A), Qr, Qc
    else:
        raise CFException("Canonical form function failed.")