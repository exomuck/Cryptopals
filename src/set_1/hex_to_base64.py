from codecs import encode, decode


# Sử dụng hàm của thư viện để decode
def hex_to_base64(htb_str):
    b64 = encode(decode(htb_str, 'hex'), 'base64').decode()
    return b64


str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print("Produce: ", hex_to_base64(str))
