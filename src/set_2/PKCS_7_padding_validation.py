from src.Utilities.Padding import pkcs7_unpad


# print(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16))
# print(pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16))  # AssertionError
