# https://learn.microsoft.com/vi-vn/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding
# https://en.wikipedia.org/wiki/ASN.1
# https://en.wikipedia.org/wiki/PKCS_1
# https://www.rfc-editor.org/rfc/rfc2313
# https://www.ibm.com/docs/en/zos/2.5.0?topic=cryptography-pkcs-1-formats
# https://crypto.stackexchange.com/questions/58600/bleichenbacher-rsa1024-signature-forgery-closed-form-solution
import hashlib
import math

from src.Utilities.rsa_publickey import RSA
from src.Utilities.Mathematics import invpow_integer


class RsaSigPkcs:
    """
    Implementation of RSA Signature.
    Based on the standard PKCS #1 Version 1.5
    https://www.rfc-editor.org/rfc/rfc2313
    Using MD5 digest.
    """
    ASN1_MD5 = b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'

    def __init__(self):
        self.rsa_obj = RSA(key_len=1024, squeeze_output=False)

    def sign(self, msg: bytes) -> int:
        # digest the message
        msg_hash = hashlib.md5(msg).digest()
        msg_hash = self.ASN1_MD5 + msg_hash

        # encode the data
        prefix = b'\x00\x01'
        padding = b'\xFF' * (self.rsa_obj.k - 3 - len(msg_hash))
        suffix = b'\x00'

        # EB = 00 || BT || PS || 00 || D
        msg_encoded = prefix + padding + suffix + msg_hash
        assert len(msg_encoded) == self.rsa_obj.k

        # convert to int and sign
        sig = self.rsa_obj.decrypt(msg_encoded, input_bytes=True, output_bytes=False)

        return sig

    def verify(self, msg: bytes, sig: int) -> bool:
        # decrypt sig and convert to bytes
        sig = self.rsa_obj.encrypt(sig, input_bytes=False, output_bytes=True)

        # find the signature  marker
        if sig[0:2] != b'\x00\x01':
            return False

        # find the 00 separator between the padding and the payload
        try:
            sep_idx = sig.index(b'\x00', 2)
            sep_idx += 1
        except ValueError:
            return False

        # parse ASN1
        if not sig[sep_idx:].startswith(self.ASN1_MD5):
            return False

        # parse hash
        msg_hash = sig[sep_idx + len(self.ASN1_MD5):sep_idx + len(self.ASN1_MD5) + 16]
        real_msg_hash = hashlib.md5(msg).digest()

        # check message integrity
        return msg_hash == real_msg_hash


# "This is a bug because it implies the verifier isn't checking all the padding.
# If you don't check the padding, you leave open the possibility that instead
# of hundreds of ffh bytes, you have only a few, which if you think about it
# means there could be squizzilions of possible numbers that could produce a
# valid-looking signature."
def forge_sig(msg: bytes, sig_len: int):
    # create ASN1 | HASH
    msg_hash = hashlib.md5(msg).digest()
    msg_hash = RsaSigPkcs.ASN1_MD5 + msg_hash

    # format the message block
    msg_encoded = b'\x00\x01\xFF\xFF\xFF\xFF\x00'
    msg_encoded += msg_hash
    msg_encoded += b'\x00' * (sig_len - len(msg_encoded))

    # transform to integer
    msg_encoded = RSA.bytes_to_integer(msg_encoded)

    # cube root the result (floor)
    sig = invpow_integer(msg_encoded, 3)

    return sig + 1


# signature fake khi được decrypt bằng key public RSA sẽ tạo 1 giá trị hash phù hợp với message
def main():
    # create signature object
    rsa_sig = RsaSigPkcs()

    # the message we choose
    msg = b'hi mom'

    # real signature
    real_sig = rsa_sig.sign(msg)

    # forged signature
    sig_len = math.ceil(math.log2(rsa_sig.rsa_obj.n) / 8)
    forged_sig = forge_sig(msg, sig_len)

    # verify signature
    real_sig_res = rsa_sig.verify(msg, real_sig)
    print(f'{real_sig_res=}')
    forged_sig_res = rsa_sig.verify(msg, forged_sig)
    print(f'{forged_sig_res=}')


if __name__ == '__main__':
    main()
