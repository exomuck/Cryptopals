from binascii import a2b_base64
from Crypto.Cipher import AES

KEY = b"YELLOW SUBMARINE"


def decrypt_aes():
    file = '../../assets/AES_in_ECB_mode.txt'
    text = ""
    for line in open(file):
        text += line.strip()
    text = a2b_base64(text)

    return AES.new(KEY, AES.MODE_ECB).decrypt(text)


if __name__ == '__main__':
    print(decrypt_aes())
