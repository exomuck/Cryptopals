from src.Utilities.AES import aes_ecb_encrypt, aes_ecb_decrypt
from Crypto.Random import get_random_bytes

# globals
AES_BLOCK_SIZE = 16


# UserProfile from somewhere on GitHub
class UserProfile:
    # Hàm khởi tạo. Tạo 1 key random với độ dài 16 byte
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)

    @staticmethod
    # Return 1 từ điển chứa các cặp key và giá trị được chia ra bằng dấu &.
    # trong mỗi cặp key với value chia ra bằng dấu =
    def key_val_parser(expression: str) -> dict:
        parsed = {}
        # split to key,val pairs
        for pair in expression.split('&'):
            # split to key and val
            key, val = pair.split('=')
            parsed[key] = val

        return parsed

    @staticmethod
    # Bỏ đi & và = trong mail sau đó nối vào dòng "mail="
    def profile_for(user_mail: str) -> str:
        # remove illegal characters
        user_mail = user_mail.replace('&', '').replace('=', '')
        # build expression
        expr = f'mail={user_mail}&uid=10&role=user'
        return expr

    # Nhập vào email, gọi lại hàm profile_for để chèn vào nội dung sau đó mã hóa nội dung bằng ecb rồi return
    def get_user_profile(self, user_mail: str) -> bytes:
        # get expression
        expr = self.profile_for(user_mail)
        expr = expr.encode('ascii')

        # encrypt the profile and send
        cipher = aes_ecb_encrypt(expr, self.key)
        return cipher

    # Giải mã cipher bằng key trong hàm init, đổi sang chuỗi ascii rồi đẩy vào từ điển ở key_val_parser rồi print ra
    def set_user_profile(self, cipher: bytes):
        # decrypt and decode the received profile
        plaintext = aes_ecb_decrypt(cipher, self.key, remove_padding=True)
        plaintext = plaintext.decode('ascii')
        parsed = self.key_val_parser(plaintext)
        print(parsed)


def attack():
    user_profile = UserProfile()

    # Tạo ra khối bắt đầu, chứa chuỗi ‘mail=foo@hackme.com&uid=10&role=’ và độ dài của chuỗi này là bội số của 16
    # -> Có thể tạo thêm 1 khối khác sau nó
    starting_blocks = user_profile.get_user_profile('foo@hackme.com')
    # Xóa đi khối cuối cùng (ban đầu nó có thể chứa 1 phần của 'role=' cùng với padding) để chèn admin vào
    starting_blocks = starting_blocks[:-AES_BLOCK_SIZE]

    # Tạo khối cuối cùng mới với 'admin' rồi chèn thêm padding vào cuối để chắc chắn admin đứng đầu trong 1 khối.
    # Ghép lại với nhau sẽ được AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    last_block_plaintext = 'admin' + '\x0b' * 11
    last_block_plaintext = 'A' * 11 + last_block_plaintext

    # Chèn payload vào hàm get_user_profile
    last_block = user_profile.get_user_profile(last_block_plaintext)
    # Lấy khối thứ 2 từ last_block (admin) -> last_block chứa khối đã mã hóa của 'admin' kèm theo padding
    # và được dùng để thêm vào khối bắt đầu -> admin sẽ xuất hiện ở sau 'role='
    last_block = last_block[AES_BLOCK_SIZE:2*AES_BLOCK_SIZE]

    # Thêm payload vào khối bắt đầu rồi chạy hàm set_user_profile
    attack_sequence = starting_blocks + last_block
    user_profile.set_user_profile(attack_sequence)


if __name__ == '__main__':
    attack()
