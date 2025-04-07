from random import randint

beta = [
    [0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1],
    [0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
    [1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1],
    [0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1],
    [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1],
    [1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0],
    [0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0],
    [1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1],
    [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0],
    [0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1],
    [0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0],
    [0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0],
    [1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0],
    [1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0]
]
S = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
     0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

P = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]


def encrypt_block(plainText: list, WK: list, K0: list, K1: list) -> list:
    """ Encrypts a block of plaintext using the given key schedule and round keys.

    Args:
        plainText (list): list of nibbles (4-bit values) representing the plaintext.
        WK (list): list of 16 nibbles (4-bit values) (XOR of K0 and K1).
        K0 (list): list of 16 nibbles (4-bit values).
        K1 (list): list of 16 nibbles (4-bit values).

    Returns:
        list: list of nibbles (4-bit values) representing the ciphertext.
    """
    state = [a ^ b for a, b in zip(WK, plainText)]
    sched = [K0, K1, K0, K1, K0, K1, K0, K1, K0, K1, K0, K1, K0, K1, K0]
    for i in range(15):
        for j in range(16):
            state[j] = S[state[j]]

        tmp = state[:]
        for j in range(16):
            tmp[j] = state[P[j]]
        state = tmp

        tmp = state[:]
        for j in range(0, 16, 4):
            state[j] = tmp[j+1] ^ tmp[j+2] ^ tmp[j+3]
            state[j+1] = tmp[j] ^ tmp[j+2] ^ tmp[j+3]
            state[j+2] = tmp[j] ^ tmp[j+1] ^ tmp[j+3]
            state[j+3] = tmp[j] ^ tmp[j+1] ^ tmp[j+2]

        state = [a ^ b for a, b in zip(state, [x ^ y for (x, y) in zip(beta[i], sched[i])])]

    for j in range(16):
        state[j] = S[state[j]]

    return [a ^ b for a, b in zip(WK, state)]


def split_nibbles(l: bytes) -> list[int]:
    """
    Splits a list of bytes into nibbles (4-bit values).
    Returns a list of nibbles (0-15)    
    """
    res = []
    for i in l:
        res.append((i >> 4) & 0xf)
        res.append(i & 0xf)
    return res


def unsplit_nibbles(l: list[int]) -> bytes:
    """ 
    Combines a list of nibbles (4-bit values) into bytes.
    Each byte is formed by combining two nibbles.
    Args:
        l (list[int]): List of nibbles (0-15).

    Returns:
        bytes: Combined bytes/list of integers.
    """
    res = []
    for i in range(0, len(l), 2):
        res.append((l[i] << 4) | l[i+1])
    return res


def compress(message_bytes: bytes) -> list[int]:
    """ 
    Compresses a ascii byte array (removes the MSB of each byte) into a list of nibbles.
    Each byte is represented by 7 bits, and the result is padded to a multiple of 8 bits.
    """
    output = []
    for b in message_bytes:
        assert b & 0x80 == 0
        output.append(format(b, '07b'))
    output_str = ''.join(output)
    if len(output_str) % 8 != 0:
        output_str += '0' * (8 - (len(output_str) % 8))
    res = []
    for i in range(0, len(output_str), 8):
        res.append(int(output_str[i:i+8], 2))
    return res


def decompress(message_bytes):
    """
    Decompresses a list of bytes into a byte array.
    Each byte is formed by combining 7 bits from the input (the remaining zeros are ignored).
    """
    bits = []
    for b in message_bytes:
        bits.append(format(b, '08b'))
    bitstr = ''.join(bits)
    bitstr = bitstr[:-(len(bitstr) % 7)]
    output = []
    for i in range(0, len(bitstr), 7):
        output.append(int(bitstr[i:i+7], 2))
    return output


def encrypt(key: bytes, message: bytes) -> bytes:
    """Encrypts a message using a key and a block cipher.

    Args:
        key (bytes): key of 16 bytes (128 bits) to be used for encryption.
        message (bytes): message to be encrypted.
    Returns:
        bytes: encrypted message.
    """
    key = split_nibbles(key) # convert key to nibbles, 32 nibbles (4 bits each)
    K0 = key[:16]   # first 16 nibbles (64 bits) of the key
    K1 = key[16:32] # second 16 nibbles (64 bits) of the key
    WK = [a ^ b for a, b in zip(K0, K1)] # XOR of K0 and K1
    padding_needed = 8 - (len(message) % 8)
    message = split_nibbles(list(message) + padding_needed * [padding_needed])
    assert len(message) % 16 == 0
    assert len(message) > 0
    # 16 nibbles per block (64 bits)
    # split message into blocks of 16 nibbles (64 bits)
    blocks = [message[i:i+16] for i in range(0, len(message), 16)]
    iv = split_nibbles([randint(0, 255) for _ in range(8)]) # 8 bytes (64 bits) IV, 16 nibbles
    output = list(iv)
    for block in blocks:
        pt = [a ^ b for (a, b) in zip(block, iv)]
        ct = encrypt_block(pt, WK, K0, K1)
        assert len(ct) == 16
        output.extend(ct)
        iv = ct
    assert all(c < 0x10 for c in output)
    return unsplit_nibbles(output)


def encrypt_single_block(key: bytes, message: bytes) -> bytes:
    """Encrypts a block message.

    Args:
        key (bytes): key of 16 bytes (128 bits) to be used for encryption.
        message (bytes): message to be encrypted.
    Returns:
        bytes: encrypted message.
    """
    assert len(message) == 8
    key = split_nibbles(key) # convert key to nibbles, 32 nibbles (4 bits each)
    K0 = key[:16]   # first 16 nibbles (64 bits) of the key
    K1 = key[16:32] # second 16 nibbles (64 bits) of the key
    WK = [a ^ b for a, b in zip(K0, K1)] # XOR of K0 and K1
    # message = int(message).to_bytes(8, 'big')
    message = split_nibbles(message)
    assert len(message) == 16
    ct = encrypt_block(message, WK, K0, K1)
    return bytes(unsplit_nibbles(ct))

if __name__ == "__main__":
    # test that the cipher in this challenge is actually Midori64
    key = b"\x00" * 16
    pt = b"\x88" * 8
    
    # weak key 1
    print("Key: ", key.hex())
    print("Plaintext: ", pt.hex())
    print("Ciphertext Check: ", encrypt_single_block(key, pt).hex() == "9998899889888899")

    key = bytes.fromhex("1100110011001100" + "0011001100110011")
    pt = bytes.fromhex("9999999999999999")
    
    # weak key 2
    print("Key: ", key.hex())
    print("Plaintext: ", pt.hex())
    print("Ciphertext Check: ", encrypt_single_block(key, pt).hex() == "8999999988988989")
    
    # normal key
    key = bytes.fromhex("687ded3b3c85b3f35b1009863e2a8cbf")
    pt = bytes.fromhex("42c20fd3b586879e")
    print("Key: ", key.hex())
    print("Plaintext: ", pt.hex())
    print("Ciphertext Check: ", encrypt_single_block(key, pt).hex() == "66bcdc6270d901cd")