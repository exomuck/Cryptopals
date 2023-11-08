from binascii import unhexlify
from Single_byte_XOR_cipher import unhex


def read_file():
    with open('../../assets/detect_single_char_xor.txt', 'r') as file:
        lines = file.readlines()
    for line in lines:
        encoded = unhexlify(line.strip('\n'))
        unhex(encoded)  # same as single byte xor cipher


if __name__ == "__main__":
    read_file()
