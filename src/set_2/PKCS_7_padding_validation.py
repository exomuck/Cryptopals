def pkcs7_unpad(s):
    assert s[-s[-1]:] == s[-1:] * s[-1]
    return s[:-s[-1]]


print(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
print(pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05"))  # AssertionError
