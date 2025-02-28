import random
from base64 import b64decode
from collections import defaultdict

from Set1.P2_Fixed_XOR import xor_byte_sequences
from Set3.P18_AES_CTR import aes_ctr

KEY = random.randbytes(16)


def read_from_file(filename):
    plaintexts = []
    with open(filename, 'r') as file:
        encoded_plaintexts = file.readlines()
    for line in encoded_plaintexts:
        plaintexts.append(b64decode(line))

    return plaintexts


def encrypt_plaintexts(plaintexts):
    ciphertexts = [aes_ctr(plaintext, KEY, fixed_once=True) for plaintext in plaintexts]

    # print([aes_ctr(ciphertext, KEY, fixed_once=True) for ciphertext in ciphertexts][0])
    return ciphertexts


def is_ascii_printable(byte):
    return byte == ord(' ') or byte == ord('.') or byte == ord(',') or ord('A') <= byte <= ord('Z') or ord('a') <= byte <= ord('z')  # Printable ASCII range


def find_whitespace_positions(xord_plaintexts, block_size=16):
    """
    XOR all bytes with whitespace
    """
    possible_positions = defaultdict(int)  # Defaults to 0 for uninitialized keys
    positions = []
    for xord_plaintext in xord_plaintexts:
        xord_block = xor_byte_sequences(xord_plaintext, b" " * block_size)
        for i, byte in enumerate(xord_block):
            if is_ascii_printable(byte):
                possible_positions[i] += 1

    for i in range(block_size):
        # If all of the XORs in that specific position result to an ascii character, consider it correct
        if len(xord_plaintexts) - 2 <= possible_positions[i] <= len(xord_plaintexts):
            positions.append(i)

    return positions


def xord_ciphertext(ciphertexts, keystream, print_it=False, block_size=16):
    answer = []
    for ciphertext in ciphertexts:
        xord_ciphertext = b""
        for i in range(0, len(ciphertext), block_size):
            cipher_block = ciphertext[i:i + block_size]
            key = keystream[:len(cipher_block)]
            xord_ciphertext += xor_byte_sequences(cipher_block, key)
        if print_it:
            print(xord_ciphertext)
        answer.append(xord_ciphertext)

    return answer


def decrypt_ciphertexts(ciphertexts, block_size=16):
    """
    XORing two ciphertexts cancels out the keystream, leaving plaintext1 XOR plaintext2.
    (cipher1 = plaintext1 ^ keystream, cipher2 = plaintext2 ^ keystream,
    (keystream ^ plaintext1 ^ keystream ^ plaintext2 = plaintext1 ^ plaintext2)
    So we will XOR ciphertexts together.
    The result is basically plaintext1 XOR plaintext2. If one of them is whitespace, it means that if we XOR it again
    with whitespace, we will get the other plaintext. We will assume that if it's an ASCII character, we found the
    keystream byte at each position where that occurs.
    """
    # Firstly, we add all ciphertexts into one big ciphertext
    # ciphertext = b"".join(ciphertexts)

    result = []

    # Now we XOR every <block_size> bytes
    for i in range(len(ciphertexts)):
        cipher1 = ciphertexts[i][:block_size]
        if len(cipher1) < block_size:
            continue
        xord_ciphertexts = []
        for j in range(len(ciphertexts)):
            for block_index in range(len(ciphertexts[j]) // block_size):
                cipher2 = ciphertexts[j][block_index * block_size:block_index * block_size + block_size]
                if i == j or len(cipher2) < block_size:
                    continue
                xord_ciphertexts.append(xor_byte_sequences(cipher1, cipher2))  # XOR bytes

        result.append(xord_ciphertexts)

    # Now result is a list, in which in each index there are all the xord ciphertexts on that ciphertext

    # This didn't work for some reason
    # for i in range(0, len(ciphertext) - block_size, block_size):
    #     cipher1 = ciphertext[i:i + block_size]
    #     xord_ciphertexts = []
    #     for j in range(0, len(ciphertext), block_size):
    #         if i == j or len(ciphertext) - 1 < j + block_size:
    #             continue
    #         cipher2 = ciphertext[j:j + block_size]
    #         xord_ciphertexts.append(xor_byte_sequences(cipher1, cipher2))  # XOR bytes
    #     result.append(xord_ciphertexts)

    # Now result is a list of lists of xord ciphertexts.
    # result[i] = all ciphertexts XOR'd with the ith ciphertext block.
    # We will try to find the whitespace in that ciphertext block. We XOR all bytes with whitespace and see
    # which position outputs a valid ASCII character. We will then check if that position outputs a valid ASCII character
    # when XORd with all the other plaintexts
    # We then managed to decrypt the keystream in that position!
    # Note: XORd plaintexts is basically the same as XORd ciphertexts

    keystream = bytearray(block_size)

    for i, xord_plaintexts in enumerate(result):
        whitespace_positions = find_whitespace_positions(xord_plaintexts)
        # print(aes_ctr(ciphertext[0:block_size], KEY, fixed_once=True))
        for position in whitespace_positions:
            keystream[position] = ciphertexts[i][position] ^ ord(' ')

    # print(keystream)

    # print_xord_ciphertext(ciphertexts, keystream, print_it=True)

    # After printing this, I had to make some adjustments.
    # The keystream is bytearray(b'\x00\xe9\x1c\x10\xde\x89x\xa6\x19&\x00\xb0[E8\x00')
    # I saw things like: b'\x8e have met them ' in the first ciphertext
    # so \x8e should be 'I' => the first keystream byte is \x8e xor ord('I')
    keystream[0] = ciphertexts[0][0] ^ ord('I')
    decrypted_ciphertexts = xord_ciphertext(ciphertexts, keystream)
    return decrypted_ciphertexts


def main():
    plaintexts = read_from_file("CTR_break_ciphertexts.txt")
    ciphertexts = encrypt_plaintexts(plaintexts)
    decrypted_ciphertexts = decrypt_ciphertexts(ciphertexts)
    for decrypted_ciphertext in decrypted_ciphertexts:
        print(decrypted_ciphertext.decode())


if __name__ == '__main__':
    main()
