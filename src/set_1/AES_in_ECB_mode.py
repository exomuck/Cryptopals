from binascii import a2b_base64
from Crypto.Cipher import AES

KEY = b"YELLOW SUBMARINE"


def decrypt_aes():
    file = '../../assets/AES_in_ECB_mode.txt'
    text = ""
    for line in open(file):
        text += line.strip()
    # a2b_base64 chuyển base64 sang nhị phân
    text = a2b_base64(text)

    # Mode ECB: Trong AES, ECB không sử dụng vector khởi tạo (IV) mà
    # trong cùng 1 khối dữ liệu sẽ có cùng 1 khối mã hóa -> Dễ bị decode hơn
    return AES.new(KEY, AES.MODE_ECB).decrypt(text)


if __name__ == '__main__':
    print(decrypt_aes())
