# https://github.polettix.it/ETOOBUSY/2022/08/15/cryptopals-10/
# https://cedricvanrompay.gitlab.io/cryptopals/challenges/09-to-13.html
# https://www.codeproject.com/Tips/5366343/Cplusplus-OpenSSL-3-1-code-for-Advance-Attack-on-A

from base64 import b64decode
from itertools import cycle
from Crypto.Cipher import AES


def fixed_xor(b1, b2):  # got this from "fixed_XOR"
    return bytes(x ^ y for x, y in zip(b1, cycle(b2)))


def aes_decrypt(ad_key, cipher, ad_mode):
    cryptor = AES.new(ad_key, AES.MODE_ECB)
    last_block = b'\x00' * 16
    decrypted = b''
    for i in range(0, len(cipher), 16):
        decrypted += fixed_xor(cryptor.decrypt(cipher[i: i + 16]), last_block)
        if ad_mode == 'cbc':
            last_block = cipher[i: i + 16]
    return decrypted


with open("../../assets/Implement_CBC_mode.txt") as fh:
    content = b64decode(fh.read())
    key = b'YELLOW SUBMARINE'
    mode = 'cbc'
    print(aes_decrypt(key, content, mode))
