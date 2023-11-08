# https://en.wikipedia.org/wiki/PKCS_7

def pkcs_padding(s, length):
    diff = length - len(s)
    return s + bytes([diff] * diff)


if __name__ == "__main__":
    print(pkcs_padding(b"YELLOW SUBMARINE", 20))
