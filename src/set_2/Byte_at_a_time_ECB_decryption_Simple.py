from An_ECB_CBC_detection_oracle import generate_key
from src.Utilities.Padding import pkcs7_pad
from src.Utilities.AES import aes_ecb_encrypt
from base64 import b64decode


random_key = generate_key()
strings = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                    b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                    b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                    b'YnkK')


# Bê nguyên từ bài An_ECB_CBC_detection_oracle vào nhưng bỏ đi đoạn random mode
def encrypt_oracle(s):
    s += strings
    s = pkcs7_pad(s, len(s) + 16 - (len(s) % 16))
    return aes_ecb_encrypt(s, random_key)


# Thử nghiệm
blocksize = 0
fb = None
last_length = len(encrypt_oracle(b'A' * blocksize))
while True:
    blocksize += 1
    new_length = len(encrypt_oracle(b'A' * blocksize))
    if new_length != last_length:
        if fb is None:
            fb = blocksize
            last_length = new_length

        else:
            # length of each encrypted block
            block_length = new_length - last_length
            # number of blocks
            count = len(encrypt_oracle(b'')) // block_length
            # length of each encryption block
            blocksize = blocksize - fb
            break


# Tìm ra chuỗi ban đầu từ chuỗi đã mã hóa
def bruteforce(oracle, block_count, blocks_length, cipher_length):
    if cipher_length is None:
        cipher_length = blocks_length

    # Tìm độ dài của chuỗi ban đầu
    length = block_count * blocks_length
    # Lưu lại các byte đã tìm được
    found = []
    # Vòng lặp for lặp qua từng byte trong chuỗi ban đầu
    for i in range(length):
        # Tạo chuỗi payload bằng 1 đống "A" với độ dài bằng độ dài của số byte chưa tìm được
        payload = b'A' * (length - len(found) - 1)

        # Ở đây gọi hàm encrypt_oracle, trả về payload đã được mã hóa
        # Lấy ra byte đầu tiên từ chuỗi sau khi được mã hóa
        # (Lấy block_count khối mã hóa đầu tiên, mỗi khối có độ dài cipher_length)
        truth = oracle(payload)[:block_count * cipher_length]

        # Duyệt qua tất cả giá trị có thể của 1 byte
        for j in range(256):
            # Thêm byte hiện tại vào cuối payload, chạy mã hóa và kiểm tra xem nếu chuỗi mới có bắt đầu bằng
            # chuỗi "truth" ở trên không, nếu có thì byte hiện tại là byte tiếp theo của chuỗi ban đầu -> append
            if oracle(payload + bytes(found + [j])).startswith(truth):
                found.append(j)
                break

    return bytes(found)


# When run un comment this lines:
# if __name__ == "__main__":
#     print(bruteforce(encrypt_oracle, count, blocksize, block_length))
