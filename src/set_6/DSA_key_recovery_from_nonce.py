# https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#:~:text=The%20Digital%20Signature%20Algorithm%20(DSA,Schnorr%20and%20ElGamal%20signature%20schemes.
# https://www.simplilearn.com/tutorials/cryptography-tutorial/digital-signature-algorithm
import hashlib
import random

from src.Utilities.Mathematics import invmod


class DSA:
    # copy paste từ đề bài
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

    def __init__(self):
        # Per-user keys
        self.x = random.randint(1, self.q - 1)  # private key
        self.y = pow(self.g, self.x, self.p)  # public key

    @staticmethod
    def hashlib_func(x):
        return int(hashlib.sha1(x).hexdigest(), 16)

    # Tạo 1 signature cho msg
    def sign(self, msg: bytes):
        s = 0
        while True:
            # Lấy 1 số ngẫu nhiên k
            k = random.randint(1, self.q - 1)
            # Tính r = (g^k mod p) mod q và s = (k^-1 * (hashlib_func(msg) + xr)) mod q
            # hashlib_func là hàm hash , nếu r = 0 hay s = 0 thì nó sẽ chọn k khác
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue

            k_inv = invmod(k, self.q)
            s = (k_inv * (self.hashlib_func(msg) + self.x * r)) % self.q
            if s != 0:
                break

        return r, s

    # Kiểm tra chữ kĩ có hợp lệ ? Kiểm tra r và s có nằm trong danh sách 1 -> q-1
    # Tính w, u1, u2, v. Nếu v = r thì chữ kí hợp lệ
    def verify(self, msg: bytes, sig: (int, int)) -> bool:
        # unpack sig
        r, s = sig

        # check signature bounds
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        w = invmod(s, self.q)
        u1 = (self.hashlib_func(msg) * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        return v == r


# https://crypto.stackexchange.com/questions/7904/attack-on-dsa-with-signatures-made-with-k-k1-k2
# k được chọn từ 1 tập hợp các số nguyên từ 1-2^16 -> bruteforce k
# Khi tìm được k thì estimate_x_given_k sẽ được sử dụng để tính xấp xỉ x
class Attack:
    def __init__(self, msg: bytes, r: int, s: int, q: int, p: int, g: int, hash_func, pub_key: int):
        self.msg = msg
        self.r, self.s = r, s
        self.q, self.p, self.g = q, p, g
        self.hash_func = hash_func
        self.pub_key = pub_key

    def estimate_x_given_k(self, k: int):
        r_inv = invmod(self.r, self.q)
        x_est = (r_inv * (self.s * k - self.hash_func(self.msg))) % self.q
        return x_est

    def detect_k(self, k_max_val: int):
        """ Find the value of k using brute-force approach """
        for k in range(1, k_max_val):
            # calc r based on k
            tmp_r = pow(self.g, k, self.p) % self.q
            if tmp_r == self.r:
                return k

    # vừa detech vừa estimate -> k và x -> test với class DSA
    def detect_private_key(self):
        k = self.detect_k(2**16)
        x = self.estimate_x_given_k(k)
        return x, k


#
def main():
    # given params
    y = int('84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
            'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
            'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
            '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
            'bb283e6633451e535c45513b2d33c99ea17', 16)

    msg = b'For those that envy a MC it can be hazardous to your health\n' \
          b'So be friendly, a matter of life and death, just like a etch-a-sketch\n'

    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    # evaluate private key
    x, k = Attack(msg=msg, r=r, s=s,
                  q=DSA.q, p=DSA.p, g=DSA.g,
                  hash_func=DSA.hashlib_func, pub_key=y).detect_private_key()
    print(f'{x=}\n{k=}')

    # test signature using x
    r_est = pow(DSA.g, k, DSA.p) % DSA.q
    assert r_est == r

    k_inv = invmod(k, DSA.q)
    s_est = (k_inv * (DSA.hashlib_func(msg) + x * r)) % DSA.q
    assert s_est == s

    # check for matching signatures
    x_fingerprint = DSA.hashlib_func(hex(x)[2:].encode())
    print(x_fingerprint == int('0954edd5e0afe5542a4adf012611a91912a3ec16', 16))


if __name__ == '__main__':
    main()
