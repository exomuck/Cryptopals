import base64
from src.Utilities.AES import AesCtr


def main():
    ciphertext = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

    aes_ctr = AesCtr(b'YELLOW SUBMARINE', nonce=bytes(8), byteorder='little')
    plaintext = aes_ctr.decrypt(ciphertext)
    print(plaintext)


if __name__ == '__main__':
    main()
