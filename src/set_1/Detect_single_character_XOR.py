from binascii import unhexlify
from Single_byte_XOR_cipher import unhex


def read_file():
    with open('../../assets/detect_single_char_xor.txt', 'r') as file:
        lines = file.readlines()
    for line in lines:
        # Đổi hexa sang nhị phân
        encoded = unhexlify(line.strip('\n'))

        # tương tự bài Single_byte_XOR_cipher
        unhex(encoded)


if __name__ == "__main__":
    read_file()
