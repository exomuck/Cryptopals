import random
from itertools import product

from Crypto.Cipher import AES


def merkle_damgard_aes128(msg: bytes, state: bytes, state_size: int) -> bytes:
    if len(state) != state_size:
        raise ValueError(f'H must have length of {state_size}')

    # pad the message
    reminder = len(msg) % AES.block_size
    if reminder > 0:
        msg += bytes(AES.block_size - reminder)

    # loop message blocks
    for i in range(0, len(msg), AES.block_size):
        # pad H to key size
        assert len(state) == state_size
        state += bytes(AES.block_size - len(state))

        # encrypt
        msg_block = msg[i:i + AES.block_size]
        state = AES.new(state, AES.MODE_ECB).encrypt(msg_block)
        state = state[:state_size]

    return state


def generate_collisions(n: int, state: bytes, state_size: int):
    """ Create a 2^n multi collision set """
    msg_set = []
    for _ in range(n):
        y1, y2, state = find_collision(state, state_size)
        msg_set.append((y1, y2))

    # return msg_set
    for i in product([0, 1], repeat=n):
        yield b''.join([block[i[idx]] for idx, block in enumerate(msg_set)])


def find_collision(state: bytes, state_size: int):
    """
    Find two messages that collide
    :param state: previous state
    :param state_size: state size in bytes
    :return: (first message, second message, next state)
    """
    if len(state) != state_size:
        raise ValueError(f'state must have length of {state_size}')

    hash_dict = {}
    while True:
        msg = random.randbytes(AES.block_size)
        hash_result = merkle_damgard_aes128(msg, state, state_size)

        # check for collision
        if hash_result in hash_dict:
            return msg, hash_dict[hash_result], hash_result
        else:
            hash_dict[hash_result] = msg


def main():
    # PART 1
    # generate collisions and verify all messages collide
    n = 4  # look for 2^n collisions
    state_size = 2  # state size in bytes
    initial_state = random.randbytes(state_size)
    msg_set = generate_collisions(n, initial_state, state_size)
    hash_vals = [merkle_damgard_aes128(msg, initial_state, state_size) for msg in msg_set]
    all_collide = hash_vals.count(hash_vals[0]) == len(hash_vals)
    print(f'{all_collide=}')

    # PART 2
    # define f and g:
    b1 = 2  # f state_size
    b2 = 4  # g state_size

    # initial states
    f_initial_state = random.randbytes(b1)
    g_initial_state = random.randbytes(b2)

    # define h = f|g
    def h(msg: bytes):
        f = merkle_damgard_aes128(msg=msg, state=f_initial_state, state_size=b1)
        g = merkle_damgard_aes128(msg=msg, state=g_initial_state, state_size=b2)
        return f + g

    # look for collision in h(x) = f(x) || g(x)
    found_collision = False
    while not found_collision:
        # generate colliding messages in f
        f_msg_set = generate_collisions(n=b2*3, state=f_initial_state, state_size=b1)

        # there's a good chance the message pool has a collision in g - find it
        hash_dict = {}
        for msg in f_msg_set:
            hash_result = merkle_damgard_aes128(msg=msg, state=g_initial_state, state_size=b2)

            # check for collision
            if hash_result in hash_dict:
                m1, m2 = msg, hash_dict[hash_result]
                found_collision = True
                break
            else:
                hash_dict[hash_result] = msg

    # verify the hash h(x) collide
    is_collision = h(m1) == h(m2)
    print(f'{is_collision=}')


if __name__ == '__main__':
    main()
