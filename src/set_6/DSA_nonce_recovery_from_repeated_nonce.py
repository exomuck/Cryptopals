from DSA_key_recovery_from_nonce import DSA
from src.Utilities.Mathematics import invmod


# evaluate k từ 2 signature khác nhau (s1-r và s2-r) với 2 message khác nhau (msg1 và msg2)
# k được sử dụng trong cả 2 chữ ký -> sự khác biệt giữa 2 chữ kí sẽ bằng sự khác biệt giữa 2 giá trị hash của message
# -> Có thể tính được k bằng cách nhân sự khác biệt của 2 hash với nghịch đảo mod của sự khác biệt giữa 2 signature
def eval_k(msg1: bytes, s1: int, msg2: bytes, s2: int) -> int:
    # domain parameters
    q = DSA.q

    # equation parts
    hm1_minus_hm2 = (DSA.hashlib_func(msg1) - DSA.hashlib_func(msg2)) % q
    s1_minus_s2 = (s1 - s2) % q
    s1_minus_s2_inv = invmod(s1_minus_s2, q)

    # calc k
    k = (hm1_minus_hm2 * s1_minus_s2_inv) % q
    return k


# Tương tự estimate ở bài trước
def estimate_x_given_k(k: int, msg: bytes, r: int, s: int):
    # domain parameters
    q, H = DSA.q, DSA.hashlib_func

    r_inv = invmod(r, q)
    x_est = (r_inv * (s * k - H(msg))) % q
    return x_est


# Trường hợp thực tế k sẽ được chọn ngẫu nhiên và thay mới với mỗi signature để tránh lỗ hổng DSA
def main():
    msg1 = b'Listen for me, you better listen for me now. '
    r1 = 1105520928110492191417703162650245113664610474875
    s1 = 1267396447369736888040262262183731677867615804316

    msg2 = b'Pure black people mon is all I mon know. '
    r2 = 1105520928110492191417703162650245113664610474875
    s2 = 1021643638653719618255840562522049391608552714967

    # eval k
    k = eval_k(msg1=msg1, s1=s1, msg2=msg2, s2=s2)
    print(f'{k=}')

    # eval x
    # change r and s as 2 examples above
    x = estimate_x_given_k(k=k, msg=msg1, r=r1, s=s1)
    print(f'{x=}')

    # check for matching signatures
    x_fingerprint = DSA.hashlib_func(hex(x)[2:].encode())
    print(x_fingerprint == int('ca8f6f7c66fa362d40760d135b763eb8527d3d52', 16))


if __name__ == '__main__':
    main()
