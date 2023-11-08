from Crypto.Random import get_random_bytes
from src.Utilities.Hash import sha1


def sha1_mac(msg: bytes, key: bytes):
    return sha1(key + msg)


def main():
    key = get_random_bytes(16)
    msg = b"Don't cheat. It won't work."
    digestion = sha1_mac(msg=msg, key=key)
    print(digestion)


if __name__ == '__main__':
    main()
