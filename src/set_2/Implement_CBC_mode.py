# https://github.polettix.it/ETOOBUSY/2022/08/15/cryptopals-10/
# https://cedricvanrompay.gitlab.io/cryptopals/challenges/09-to-13.html
# https://www.codeproject.com/Tips/5366343/Cplusplus-OpenSSL-3-1-code-for-Advance-Attack-on-A

from base64 import b64decode
from itertools import cycle
from src.Utilities.AES import aes_cbc_decrypt


# Định nghĩa hàm fixed xor lấy từ bài fixed_XOR rồi rút gọn lại
# Thực hiện phép XOR giữa 2 chuỗi byte (b1 và b2)
def fixed_xor(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, cycle(b2)))


# with open("../../assets/Implement_CBC_mode.txt") as fh:
#     content = b64decode(fh.read())
#     key = b'YELLOW SUBMARINE'
#     print(aes_cbc_decrypt(content, key))
