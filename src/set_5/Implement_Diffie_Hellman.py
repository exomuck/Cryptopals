import random
from src.Utilities.Mathematics import power_mod


def main():
    # example (làm theo đề bài)
    p, g = 37, 5

    # secret (làm theo đề bài)
    a = random.randint(1, 37)
    b = random.randint(1, 37)

    # public keys
    A = (g ** a) % p
    B = (g ** b) % p

    # session key
    s1 = (A ** b) % p
    s2 = (B ** a) % p
    assert s1 == s2

    # bignums example
    p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80d'
            'c1cd129024e088a67cc74020bbea63b139b22514a08'
            '798e3404ddef9519b3cd3a431b302b0a6df25f14374'
            'fe1356d6d51c245e485b576625e7ec6f44c42e9a637'
            'ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f241'
            '17c4b1fe649286651ece45b3dc2007cb8a163bf0598'
            'da48361c55d39a69163fa8fd24cf5f83655d23dca3a'
            'd961c62f356208552bb9ed529077096966d670c354e'
            '4abc9804f1746c08ca237327ffffffffffffffff ', 16)

    g = 2

    # secret
    a = random.randint(1, p)
    b = random.randint(1, p)

    # public keys
    A = power_mod(g, a, p)
    B = power_mod(g, b, p)

    # session key
    s1 = power_mod(A, b, p)
    s2 = power_mod(B, a, p)
    # return s1, s2
    assert s1 == s2


if __name__ == '__main__':
    main()
