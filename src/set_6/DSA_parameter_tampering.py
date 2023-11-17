# https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.includehelp.com%2Fcryptography%2Fdigital-signature-algorithm-dsa.aspx&psig=AOvVaw0pKbC5BV3uQ0CWC0fcYGv6&ust=1700290236125000&source=images&cd=vfe&ved=0CBIQjhxqFwoTCOjb_Z3FyoIDFQAAAAAdAAAAABAE
import hashlib
import random

from src.Utilities.Mathematics import invmod


# Tương tự bài DSA_key_recovery_from_nonce chỉ thay đổi 1 ít ở class DSA
class DSA:
    p = int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
            '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
            '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
            'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
            'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
            '1a584471bb1', 16)

    q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

    g = int('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
            '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
            '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
            '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
            '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
            '9fc95302291', 16)

    def __init__(self, override_g=None):
        # Per-user keys
        self.x = random.randint(1, self.q - 1)  # private key
        self.y = pow(self.g, self.x, self.p)  # public key

        # Thêm đoạn này
        if override_g is not None:
            self.g = override_g

    @staticmethod
    def hashlib_func(x):
        return int(hashlib.sha1(x).hexdigest(), 16)

    def sign(self, msg: bytes) -> (int, int):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q

            k_inv = invmod(k, self.q)
            s = (k_inv * (self.hashlib_func(msg) + self.x * r)) % self.q
            if s != 0:
                break

        return r, s

    def verify(self, msg: bytes, sig: (int, int)) -> bool:
        # unpack sig
        r, s = sig

        w = invmod(s, self.q)
        u1 = (self.hashlib_func(msg) * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        return v == r


def main():
    # example 1
    dsa = DSA(override_g=0)
    msg = b'Hello, world'

    sig = dsa.sign(msg)
    print(sig)

    print(dsa.verify(msg, sig))
    print(dsa.verify(b'Goodbye, world', (0, 85478656467)))

    # example 2
    # dsa = DSA(override_g=DSA.p+1)
    #
    # z = 4
    # z_inv = invmod(z, dsa.q)
    # r = pow(dsa.y, z, dsa.p) % dsa.q
    # s = (z_inv * r) % dsa.q
    # magic_sig = (r, s)
    #
    # print(dsa.verify(b'Goodbye, world', magic_sig))


if __name__ == '__main__':
    main()
