# https://viblo.asia/p/cryptopals-set-2-block-crypto-E375zQ7jlGW

from Implement_CBC_mode import fixed_xor
from Implement_PKCS_7_padding import pkcs_padding
from Crypto.Cipher import AES
from random import randint


# Almost the same as "Implement_PKCS_7_padding" but instead of decrypt, we encrypt
def aes_encrypt(ae_key, ae_cipher, ae_mode):
    cryptor = AES.new(ae_key, AES.MODE_ECB)
    last_block = b'\x00' * 16
    encrypted = b''
    for _ in range(0, len(ae_cipher), 16):
        last_block = cryptor.encrypt(fixed_xor(ae_cipher[_: _ + 16], last_block))
        encrypted += last_block
        if ae_mode == 'ecb':
            last_block = b'\x00' * 16
    return encrypted


def generate_key(length=16):
    return bytes([randint(0, 255) for _ in range(length)])


def encryption_oracle(s):
    if randint(0, 1) == 0:
        eo_mode = 'ecb'
    else:
        eo_mode = 'cbc'
    # eo_mode = 'ecb' if randint(0, 1) == 0 else 'cbc'
    s = generate_key(randint(5, 10)) + s + generate_key(randint(5, 10))
    s = pkcs_padding(s, len(s) + 16 - (len(s) % 16))
    return aes_encrypt(generate_key(), s, eo_mode), eo_mode


# When run un comment this lines:
# for i in range(100):
#     cipher, mode = encryption_oracle(b'a' * (16 * 3))
#     if cipher[16:32] == cipher[32:48]:
#         if mode != 'ecb':
#             print('wrong')
#         else:
#             print(mode)
#     else:
#         if mode != 'cbc':
#             print('wrong')
#         else:
#             print(mode)
