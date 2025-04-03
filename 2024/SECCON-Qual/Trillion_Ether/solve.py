# slot info: 
# user address: adr
# WalletID            SlodID                    Content
# adr - 2     keccak(0) + 3*(adr - 2) + 0       adr - 1 
# adr - 2     keccak(0) + 3*(adr - 2) + 1       0
# adr - 2     keccak(0) + 3*(adr - 2) + 2       adr
# adr - 1     keccak(0) + 3*(adr - 1) + 0       adr
# adr - 1     keccak(0) + 3*(adr - 1) + 1       0
# adr - 1     keccak(0) + 3*(adr - 1) + 2       adr

# 3 * walletid  % 2^256 = 3*(adr - 2) + 2
# 2**256 % 3 = 1
# let WalletID = adr - 1  + 2*(2**256 // 3) 
#              = adr - 1 +  2*(2**256 -1) / 3
# then the slodID = 3 * (adr - 1  + 2*(2**256 -1) / 3)
#                 = keccak(0) + 3 * adr - 3 + 2**256 - 2 % 2**256
#                 = keccak(0) + 3 * adr - 5
#                 = keccak(0) + 3 * (adr - 2) + 1
# For WalletID = adr - 1  + 2*(2**256 // 3): 
# Name:     keccak(0) + 3*(adr - 2) + 1       0
# Balance:  keccak(0) + 3*(adr - 2) + 2       adr
# Address:  keccak(0) + 3*(adr - 1) + 0       adr
# We now have a wallet with balance amount being our address!
