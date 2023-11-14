import base64
from Crypto.Random import get_random_bytes

from src.set_1.Break_repeating_key_XOR import decode_single_byte_xor_cypher, divide_blocks
from src.Utilities.AES import AesCtr
from src.Utilities.Byte_Calculations import xor_bytes

# globals
AES_BLOCK_SIZE = 16


# Tương tự bài trước nhưng viết khác đi
def break_fixed_nonce_ctr_statistically(streams: list[bytes]) -> bytes:
    # transform into repeating xor cipher
    # Tìm độ dài nhỏ nhất của các luồng (bài trước tìm lớn nhất)
    min_len = min(map(len, streams))

    # Nối các phần của mỗi luồng có độ dài = min len
    ciphertext = b''.join([stream[:min_len] for stream in streams])

    # chia thành các khối như ở set 1
    block_list = divide_blocks(ciphertext, min_len)

    # Khôi phục khóa bằng hàm decode
    key_stream = bytes(map(decode_single_byte_xor_cypher, block_list))
    return key_stream


def main():
    # load file and base64 decode
    with open('../../assets/Break_fixed_nonce_CTR_statistically.txt', 'r') as fh:
        lines = fh.readlines()
    strings = list(map(base64.b64decode, lines))

    # encrypt all the lines with the same nonce
    key = get_random_bytes(AES_BLOCK_SIZE)
    aes_ctr = AesCtr(key=key, nonce=bytes(8), byteorder='little')
    strings_enc = list(map(aes_ctr.encrypt, strings))

    # detect key stream
    key_stream = break_fixed_nonce_ctr_statistically(strings_enc)

    # decrypt the strings
    for stream in strings_enc:
        stream = stream[:len(key_stream)]
        decrypted_string = xor_bytes((stream, key_stream))
        print(decrypted_string)


if __name__ == '__main__':
    main()
