import random

from CBC_MAC_Message_Forgery import CbcMac

from src.Utilities.Byte_Calculations import xor_bytes
from src.Utilities.AES import aes_cbc_encrypt

AES_BLOCK_SIZE = 16


def forge_msg(new_msg: bytes, original_msg: bytes, key: bytes) -> bytes:
    while True:
        suffix = bytes([random.randint(32, 126) for _ in range(AES_BLOCK_SIZE)])
        tmp_iv = aes_cbc_encrypt(new_msg + suffix, key=key, add_padding=False)[-AES_BLOCK_SIZE:]
        overlap_block = xor_bytes((tmp_iv, original_msg[:AES_BLOCK_SIZE]))
        try:

            overlap_block.decode('ascii')
            break
        except UnicodeDecodeError:
            continue

    final_msg = new_msg + suffix + overlap_block + original_msg[AES_BLOCK_SIZE:]
    return final_msg


def main():
    # original message
    key = b'YELLOW SUBMARINE'
    msg = b"alert('MZA who was that?');\n"
    mac = CbcMac.sign(msg, key=key, iv=bytes(AES_BLOCK_SIZE))
    assert mac.hex() == '296b8d7cb78a243dda4d0a61d33bbdd1'

    # forged mac
    new_msg = b"alert('Ayo, the Wu is back!');" + b'//'
    final_msg = forge_msg(new_msg, msg, key)
    assert CbcMac.verify(final_msg, sig=mac, key=key, iv=bytes(AES_BLOCK_SIZE))

    print(final_msg.decode('ascii'))


if __name__ == '__main__':
    main()
