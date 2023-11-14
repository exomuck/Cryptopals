import random
from Crypto.Random import get_random_bytes
from base64 import b64decode

from src.Utilities.AES import aes_cbc_decrypt, aes_cbc_encrypt
from src.Utilities.Byte_Calculations import xor_bytes
from src.Utilities.Padding import pkcs7_unpad

# globals
AES_BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.nonce = get_random_bytes(AES_BLOCK_SIZE)
        self.data = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                     b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                     b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                     b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                     b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                     b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                     b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                     b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                     b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                     b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

    def encrypt(self) -> tuple[bytes, bytes]:
        # select rand string
        plaintext = random.choice(self.data)
        # pad and encrypt
        ciphertext = aes_cbc_encrypt(plaintext, key=self.key, nonce=self.nonce, add_padding=True)
        return ciphertext, self.nonce

    def decrypt(self, ciphertext: bytes) -> bool:
        try:
            aes_cbc_decrypt(ciphertext, key=self.key, nonce=self.nonce, remove_padding=True)
            return True
        except ValueError:
            return False


def decrypt_block_mask(oracle: Oracle, current_block: bytes) -> bytes:
    # initialize empty mask
    # https://www.programiz.com/python-programming/methods/built-in/bytearray
    mask = bytearray(AES_BLOCK_SIZE)

    # decrypt byte at a time from end to start
    for byte_idx in range(AES_BLOCK_SIZE-1, -1, -1):
        # build previous block
        pad_value = AES_BLOCK_SIZE - byte_idx
        last_block = bytearray(xor_bytes((bytes([pad_value] * AES_BLOCK_SIZE), mask)))

        # iterate values until the padding is correct (bruteforce)
        for byte_val in range(2**8):
            last_block[byte_idx] = byte_val
            sequence = last_block + current_block

            # stop when the padding is correct
            if oracle.decrypt(sequence):
                # we know the plaintext byte value, so we calc the mask byte value
                mask[byte_idx] = byte_val ^ pad_value
                break

    return mask


def padding_attack(oracle: Oracle, ciphertext: bytes, iv: bytes) -> bytes:
    # verify input
    if len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError('ciphertext doesnt have proper padding')

    plaintext = bytes()
    last_block = iv
    for block_loc in range(0, len(ciphertext), AES_BLOCK_SIZE):
        # decrypt current block
        current_block = ciphertext[block_loc:block_loc+AES_BLOCK_SIZE]
        mask = decrypt_block_mask(oracle, current_block)
        plaintext += xor_bytes((last_block, mask))

        # update last block for next iteration
        last_block = current_block

    # remove padding and return
    return pkcs7_unpad(plaintext, AES_BLOCK_SIZE)


def main():
    oracle = Oracle()
    for _ in range(100):
        ciphertext, iv = oracle.encrypt()
        plaintext = padding_attack(oracle, ciphertext, iv)
        print(b64decode(plaintext))
        assert plaintext in oracle.data

    print('All tests passed successfully')


if __name__ == '__main__':
    main()
