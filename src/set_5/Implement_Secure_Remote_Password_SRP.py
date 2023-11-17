# https://www.linkedin.com/pulse/what-secure-remote-password-synologyc2/
# https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
import hashlib
import hmac
import secrets

from Crypto.Util.number import long_to_bytes


def hash_func(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)


def main():
    """ SRP demo """
    # BOTH: Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    N = """00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
           4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
           c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
           97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
           c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
           c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
           16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
           9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:"""

    N = int("".join(N.split()).replace(":", ""), 16)
    g, k = 2, 3

    I = 'Unbreakable@key.com'
    P = 'StrongPassword'

    # SERVER:
    salt = secrets.randbits(64)  # Salt for the user
    x = hash_func(salt, P)  # Private key
    v = pow(g, x, N)  # Password verifier
    print("\nServer stores (I, s, v) in its password database")
    print(f'{I = }\n{P = }\n{salt = }\n{x = }\n{v = }')

    # CLIENT to SERVER: Send I, A=g**a % N
    print("\nClient sends username I and public ephemeral value A to the server")
    a = secrets.randbits(1024)
    A = pow(g, a, N)
    print(f"{I = }\n{A = }")

    # SERVER to CLIENT: Send salt, B=kv + g**b % N
    print("\nServer sends user's salt s and public ephemeral value B to client")
    b = secrets.randbits(1024)
    B = (k * v + pow(g, b, N)) % N
    print(f"{salt = }\n{B = }")

    # BOTH: Compute string uH = SHA256(A|B), u = integer of uH
    print("\nClient and server calculate the random scrambling parameter")
    u = hash_func(A, B)
    print(f"{u = }")

    # CLIENT:
    print("\nClient computes session key")
    x = hash_func(salt, P)
    S_c = pow(B - k * pow(g, x, N), a + u * x, N)
    K_c = hash_func(S_c)
    print(f"{S_c = }\n{K_c = }")

    # SERVER:
    print("\nServer computes session key")
    S_s = pow(A * pow(v, u, N), b, N)
    K_s = hash_func(S_s)
    print(f"{S_s = }\n{K_s = }")

    assert K_s == K_c

    # SERVER verify CLIENT:
    client_verification = hmac.digest(key=long_to_bytes(K_c), msg=long_to_bytes(salt), digest='sha256')
    if hmac.digest(key=long_to_bytes(K_s), msg=long_to_bytes(salt), digest='sha256') != client_verification:
        print('Client verification failed')


# Tạo 1 khóa riêng a và b ngẫu nhiên sau đó tính key public bằng lũy thừa g với key rồi % p -> A và B
# Tính tham số ngẫu nhiên u bằng cách hash sha256 A và B
# Tính s1 và s2 -> Xác nhận key giống nhau (K_s = K_c)
if __name__ == '__main__':
    main()
