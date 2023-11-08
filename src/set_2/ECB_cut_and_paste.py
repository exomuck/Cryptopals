from src.Utilities.AES import aes_ecb_encrypt, aes_ecb_decrypt
from Crypto.Random import get_random_bytes

# globals
AES_BLOCK_SIZE = 16


class UserProfile:
    def __init__(self):
        self.key = get_random_bytes(AES_BLOCK_SIZE)

    @staticmethod
    def key_val_parser(expression: str) -> dict:
        parsed = {}
        # split to key,val pairs
        for pair in expression.split('&'):
            # split to key and val
            key, val = pair.split('=')
            parsed[key] = val

        return parsed

    @staticmethod
    def profile_for(user_mail: str) -> str:
        # remove illegal characters
        user_mail = user_mail.replace('&', '').replace('=', '')
        # build expression
        expr = f'mail={user_mail}&uid=10&role=user'
        return expr

    def get_user_profile(self, user_mail: str) -> bytes:
        # get expression
        expr = self.profile_for(user_mail)
        expr = expr.encode('ascii')

        # encrypt the profile and send
        cipher = aes_ecb_encrypt(expr, self.key)
        return cipher

    def set_user_profile(self, cipher: bytes):
        # decrypt and decode the received profile
        plaintext = aes_ecb_decrypt(cipher, self.key, remove_padding=True)
        plaintext = plaintext.decode('ascii')
        parsed = self.key_val_parser(plaintext)
        print(parsed)


def attack():
    user_profile = UserProfile()

    # generate the initial blocks which contain the string: 'mail=foo@hackme.com&uid=10&role='
    # this string length is a multiple of AES block length,
    # that way, we will be able to append another block after it.
    starting_blocks = user_profile.get_user_profile('foo@hackme.com')
    starting_blocks = starting_blocks[:-AES_BLOCK_SIZE]  # remove last block

    # generate the last block which contain the string 'admin' and PKCS7 padding.
    # we encrypt its plaintext, by padding its start by 11 and aligning it to the second block.
    # that way, the input plaintext become:
    # block1 - 'mail=AAAAAAAAAAA'
    # block2 - 'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
    # block3 - etc.
    last_block_plaintext = 'admin' + '\x0b' * 11
    last_block_plaintext = 'A' * 11 + last_block_plaintext
    last_block = user_profile.get_user_profile(last_block_plaintext)
    last_block = last_block[AES_BLOCK_SIZE:2*AES_BLOCK_SIZE]  # extract second block

    # connect blocks to create the attack sequence
    attack_sequence = starting_blocks + last_block
    user_profile.set_user_profile(attack_sequence)


if __name__ == '__main__':
    attack()
