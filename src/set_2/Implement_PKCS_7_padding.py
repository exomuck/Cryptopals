# https://en.wikipedia.org/wiki/PKCS_7

from src.Utilities.Padding import pkcs7_pad


if __name__ == "__main__":
    print(pkcs7_pad(b"YELLOW SUBMARINE", 20))
