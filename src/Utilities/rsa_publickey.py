# https://pypi.org/project/rsa/
# https://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python
# https://www.geeksforgeeks.org/rsa-algorithm-cryptography/
import math

from Crypto.Util.number import getPrime

from src.Utilities.Mathematics import invmod


class RsaBase:
    def __init__(self, key_len: int = 1024):
        n = 0
        e = 0
        d = 0
        # key gen
        while True:
            # repeat until we find et which is co-prime to e
            try:
                # Generate 2 random primes
                p, q = getPrime(key_len//2), getPrime(key_len//2)

                # RSA math is modulo n
                n = p * q

                # calc the "totient"
                et = (p - 1) * (q - 1)
                e = 3

                # calc private key
                d = invmod(e, et)
                break

            except ValueError:
                continue

        # keys summery
        self.n = n
        self.e = e
        self._d = d

        # length of modulus in octets
        self.k = math.ceil(math.log2(n) / 8)

    def encrypt_base(self, m: int) -> int:
        c = pow(m, self.e, self.n)
        return c

    def decrypt_base(self, c: int) -> int:
        m = pow(c, self._d, self.n)
        return m

    @staticmethod
    def bytes_to_integer(stream: bytes) -> int:
        return int.from_bytes(stream, byteorder='big')

    def integer_to_bytes_padded(self, num: int) -> bytes:
        return int.to_bytes(num, self.k, byteorder='big')

    @staticmethod
    def integer_to_bytes_squeezed(num: int) -> bytes:
        bytes_len = math.ceil(num.bit_length() / 8)
        return int.to_bytes(num, bytes_len, byteorder='big')


class RSA(RsaBase):
    def __init__(self, key_len: int = 1024, squeeze_output: bool = True):
        super().__init__(key_len)

        # choose integer-to-bytes conversion
        if squeeze_output:
            self.integer_to_bytes = self.integer_to_bytes_squeezed
        else:
            self.integer_to_bytes = self.integer_to_bytes_padded

    def encrypt(self, m, input_bytes=True, output_bytes=False):
        if input_bytes:
            m = self.bytes_to_integer(m)

        c = self.encrypt_base(m)

        if output_bytes:
            c = self.integer_to_bytes(c)

        return c

    def decrypt(self, c, input_bytes=False, output_bytes=True):
        if input_bytes:
            c = self.bytes_to_integer(c)

        m = self.decrypt_base(c)

        if output_bytes:
            m = self.integer_to_bytes(m)

        return m
