import random

class python_int:
    
    def __init__(self, value: int):
        self.value = value
        self.stored_bits = self.complement_bits(value)
        self.bit_length = len(self.stored_bits)
        self.signed = 1 if value < 0 else 0
        
    @staticmethod
    def complement_bits(value: int):
        bit_length = 1 if value == 0 else value.bit_length()
        if value < 0:
            bits = bin((1 << bit_length) + value)[2:].zfill(bit_length)
        else:
            bits = bin(value)[2:].zfill(bit_length)
        return bits
    
    @staticmethod
    def integer_value(bits: str, signed: bool):
        if signed:
            return int(bits, 2) - (1 << len(bits))
        return int(bits, 2)
    
    def bits(self, fixed_width: int = None):
        """ Returns the stored bits of the number in binary format (the signed bit is not included in the string).

        Args:
            fixed_width (int, optional): the number of bits aligned. Defaults to None.

        Raises:
            ValueError: fixed_width must be greater than or equal to the bit length of the number

        Returns:
            str: the binary representation of the number
        """
        if fixed_width is None:
            return self.stored_bits
        if fixed_width < len(self.stored_bits):
            raise ValueError("fixed_width must be greater than or equal to the bit length of the number")
        if fixed_width >= len(self.stored_bits):
            return self.stored_bits.rjust(fixed_width, str(self.signed))

    def __xor__(self, other):
        if isinstance(other, python_int):
            nbit = max(self.bit_length, other.bit_length)
            bits1 = self.bits(nbit)
            bits2 = other.bits(nbit)
            result_bits = ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))
            signed = self.signed ^ other.signed
            return python_int(self.integer_value(result_bits, signed))
        return NotImplementedError("Unsupported operand type(s) for ^: 'python_int' and '{}'".format(type(other)))

    def __repr__(self):
        return f"{self.value}"

    def __int__(self):
        return self.value
    
    def __eq__(self, other):
        if isinstance(other, python_int):
            return self.value == other.value
        elif isinstance(other, int):
            return self.value == other
        else:
            return NotImplementedError("Unsupported operand type(s) for ==: 'python_int' and '{}'".format(type(other)))
   
print(python_int(-3).bits(8))
print(python_int(-4).bits(8)) 

for v1 in [3, -3]:
    for v2 in [4, -4]:
        p1 = python_int(v1)
        p2 = python_int(v2)
        check = p1 ^ p2 == v1 ^ v2
        print(f"{check =}")
        
v1 = random.randint(1, 2**64)
v2 = -random.randint(1, 2**64)
p1 = python_int(v1)
p2 = python_int(v2)
print(f"{p1.bits(64) = }, with value {v1}")
print(f"{p2.bits(64) = }, with value {v2}")
check = p1 ^ p2 == v1 ^ v2
print(f"{check =}")