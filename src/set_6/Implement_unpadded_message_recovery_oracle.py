# https://en.wikipedia.org/wiki/RSA_(cryptosystem)
# https://crypto.stackexchange.com/questions/3608/why-is-padding-used-for-rsa-encryption-given-that-it-is-not-a-block-cipher
# https://www.simplilearn.com/tutorials/cryptography-tutorial/rsa-algorithm
import random
import time
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
from src.Utilities.rsa_publickey import RSA
from src.Utilities.Mathematics import invmod


class Server:
    def __init__(self):
        self.rsa_obj = RSA(512)
        self.prev_msg = []
        self.timestamps = []

    def encrypt(self, msg: bytes) -> int:
        return self.rsa_obj.encrypt(msg)

    def decrypt(self, ciphertext: int) -> bytes:
        # check for older decryption
        msg_hash = sha256(long_to_bytes(ciphertext)).digest()
        if msg_hash in self.prev_msg:
            raise PermissionError('The message has already been decrypted.')

        # update history
        self.prev_msg.append(msg_hash)
        self.timestamps.append(time.time())

        # decrypt the message
        plaintext = self.rsa_obj.decrypt(ciphertext)
        return plaintext


# Server decrypt mọi data nhận được mà không kiểm tra xem có hợp lệ không
# -> Gửi thông tin sai -> Nhận được plaintext -> ciphertext
def attack(server: Server, ciphertext: int) -> bytes:
    # some consts
    N = server.rsa_obj.n
    e = server.rsa_obj.e

    s = random.randint(2, N - 1)
    s_inv = invmod(s, N)

    # create fake ciphertext
    fake_ciphertext = (pow(s, e, N) * ciphertext) % N

    # decrypt
    p_fake = RSA.bytes_to_integer(server.decrypt(fake_ciphertext))
    p = (s_inv * p_fake) % N
    p = server.rsa_obj.integer_to_bytes(p)

    return p


def main():
    server = Server()

    # encrypt message
    msg = b'Implement unpadded message recovery oracle'
    c = server.encrypt(msg)

    # first decryption
    p = server.decrypt(c)
    print(f'{p=}')

    # second decryption
    try:
        server.decrypt(c)
    except PermissionError:
        print('Second attempt failed successfully :)')

    # attack
    rec_p = attack(server, c)
    print(f'{rec_p=}')


if __name__ == '__main__':
    main()
