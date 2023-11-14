# https://viblo.asia/p/cryptopals-set-2-block-crypto-E375zQ7jlGW

from Implement_CBC_mode import fixed_xor
from src.Utilities.Padding import pkcs7_pad
from Crypto.Cipher import AES
from random import randint


# Hàm mã hóa 1 chuỗi bằng AES, gần tương tự với AES trong Utilities nhưng đã sửa lại để có thêm ae_mode
def aes_encrypt(ae_key, ae_cipher, ae_mode):
    cryptor = AES.new(ae_key, AES.MODE_ECB)

    # Tạo 1 khối dữ liệu trống 16 byte và 1 chuỗi để lưu kết quả
    last_block = b'\x00' * 16
    encrypted = b''

    # Duyệt qua lần lượt 16 byte trong chuỗi cần mã hóa
    for _ in range(0, len(ae_cipher), 16):
        # Thực hiện phép XOR giữa khối hiện tại và khối cuối cùng, sau đó mã hóa kết quả bằng AES
        last_block = cryptor.encrypt(fixed_xor(ae_cipher[_: _ + 16], last_block))
        encrypted += last_block
        if ae_mode == 'ecb':
            last_block = b'\x00' * 16
    return encrypted


# Tạo 1 key bất kì độ dài 16
def generate_key():
    return bytes([randint(0, 255) for _ in range(16)])


# Dự đoán phép mã hóa, chọn bất kì ecb hoặc cbc, thêm padding vào chuỗi s để đảm bảo độ dài chuỗi là bội số của 16
# vì mã hóa bằng AES hoạt động trên 1 khối dữ liệu 16 bytes
def encryption_oracle(s):
    if randint(0, 1) == 0:
        eo_mode = 'ecb'
    else:
        eo_mode = 'cbc'
    s = pkcs7_pad(s, len(s) + 16 - (len(s) % 16))
    return aes_encrypt(generate_key(), s, eo_mode), eo_mode


# When run un comment these lines:
# ecb: cùng 1 khối dữ liệu sẽ được mã hóa thành cùng 1 khối mã hóa do không có iv
# cbc: cùng 1 khối dữ liệu mỗi khối mã hóa sẽ phụ thuộc và khối trước đó -> không khối nào giống khối nào
# for i in range(100):
#     # Thử nghiệm hàm dự đoán phép mã hóa bằng cách chạy mã hóa 1 chuỗi 3 khối 16 byte sau đó kiểm tra chế độ mã hóa
#     cipher, mode = encryption_oracle(b'a' * (16 * 3))
#
#     # Nếu 2 khối mã hóa liên tiếp giống nhau thì chế độ mã hóa sẽ là ecb, ngược lại là cbc
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
