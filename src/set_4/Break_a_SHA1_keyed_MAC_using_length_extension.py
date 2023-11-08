import struct
from Crypto.Random import get_random_bytes
from Implement_a_SHA_1_keyed_MAC import sha1_mac
from src.Utilities.Hash import sha1


def md_padding(msg_len: int) -> bytes:
    # message length in bits
    ml = msg_len * 8

    # append the bit '1' to the message
    padding = bytes([0x80])

    # append bits '0' to match len of 448 (mod 512) bits
    pad_len = (448 // 8) - ((msg_len + len(padding)) % (512 // 8))
    pad_len = (512 // 8) + pad_len if pad_len < 0 else pad_len
    padding += bytes(pad_len)

    # append ml, the original message length in bits, as a 64-bit big-endian integer.
    padding += ml.to_bytes(64 // 8, byteorder='big')

    # the total length is a multiple of 512 bits (64 bytes)
    assert ((msg_len + len(padding)) % 64 == 0)

    return padding


def attack(org_msg: bytes, org_mac: bytes, new_msg: bytes, key_len: int):
    # unpack sha1 state
    h0, h1, h2, h3, h4 = [struct.unpack('>I', org_mac[i:i + 4])[0] for i in range(0, 20, 4)]

    # build final message
    msg_len = key_len + len(org_msg)
    padding = md_padding(msg_len)
    final_msg = org_msg + padding + new_msg

    # build new hash
    fake_len = len(final_msg) + key_len
    forged_mac = sha1(new_msg, h0=h0, h1=h1, h2=h2, h3=h3, h4=h4, force_len=fake_len)

    return final_msg, forged_mac


def main():
    # create SHA-1 keyed MAC on original message
    key = get_random_bytes(16)
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = sha1_mac(msg=msg, key=key)
    print(f'{mac=}')

    # generate fake SHA-1 keyed MAC
    key_len = 16
    new_msg = b";admin=true"
    final_msg, forged_mac = attack(org_msg=msg, org_mac=mac, new_msg=new_msg, key_len=key_len)
    print(f'{final_msg=}')
    print(f'{forged_mac=}')

    # check for [forged_mac] validity
    new_mac = sha1_mac(msg=final_msg, key=key)
    print(forged_mac == new_mac)


if __name__ == '__main__':
    main()
