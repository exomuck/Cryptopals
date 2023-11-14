import base64
from Crypto.Random import get_random_bytes
from src.Utilities.Byte_Calculations import xor_bytes
from src.Utilities.AES import aes_ecb_decrypt, AesCtr

# globals
AES_BLOCK_SIZE = 16


class EditOracle:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)
        self.ctr_obj = AesCtr(self.key)

    def get_cipher(self):
        # load cipher and decode base64 to bytes
        with open('../../assets/Break_random_access_read_write_AES_CTR.txt', 'r') as fh:
            source = base64.b64decode(fh.read())

        key = b"YELLOW SUBMARINE"
        plaintext = aes_ecb_decrypt(ciphertext=source, key=key, remove_padding=True)

        # encrypt under CTR mode
        ciphertext = self.ctr_obj.encrypt(plaintext)
        return ciphertext

    def edit(self, ciphertext: bytes, offset: int, new_text: bytes):
        # Phương thức này cho phép bạn thay thế một phần của ciphertext bằng văn bản mới.
        # Nó tạo ra một keystream có độ dài giống như ciphertext bằng cách sử dụng đối tượng CTR.
        # Sau đó, nó cắt keystream từ offset đến độ dài của văn bản mới.
        # Ciphertext mới được tạo bằng cách XOR keystream đã cắt với văn bản mới.
        key_stream = self.ctr_obj.generate_key_stream(len(ciphertext))
        key_stream = key_stream[offset: offset + len(new_text)]

        new_cipher = xor_bytes((key_stream, new_text))
        out = ciphertext[:offset] + new_cipher + ciphertext[offset + len(new_cipher):]
        return out


def main():
    oracle = EditOracle()
    ciphertext = oracle.get_cipher()

    # attack
    recovered_plaintext = oracle.edit(ciphertext=ciphertext, offset=0, new_text=ciphertext)
    print(recovered_plaintext)


if __name__ == '__main__':
    main()
