import base64
import random

from Set1.P6_break_repeating_xor import find_best_key_and_plaintext, break_into_blocks, transpose_blocks
from Set1.P2_Fixed_XOR import xor_byte_sequences
from Set3.P18_AES_CTR import aes_ctr

KEY = random.randbytes(16)  # Fixed key for testing
NONCE = 0  # Fixed nonce


def read_ciphertexts(filename):
    with open(filename, 'r') as f:
        plaintexts = [base64.b64decode(line.strip()) for line in f]
    return plaintexts


def encrypt_ciphertexts(plaintexts):
    return [aes_ctr(pt, KEY, fixed_once=True) for pt in plaintexts]


def recover_keystream(ciphertexts, block_size=16):
    min_length = min(len(ct) for ct in ciphertexts)  # Truncate to shortest length

    # The maximum length of the keystream is the block size, so if it's greater than that, we will use the block size
    if min_length > block_size:
        min_length = block_size
    truncated_ciphertexts = [ct[:min_length] for ct in ciphertexts]

    blocks = break_into_blocks(b"".join(truncated_ciphertexts), min_length)  # Create blocks



    # Transpose to analyze keystream reuse
    # (make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    transposed_blocks = transpose_blocks(blocks, min_length)

    keystream = bytearray()
    for block in transposed_blocks:
        best_key, _ = find_best_key_and_plaintext(block)  # Solve as single-byte XOR
        keystream.append(best_key)

    # print(keystream)
    # Here, there is a small problem with the first byte: I get the result:
    # keystream: bytearray(b'\xe6\xa7"j\x02\xd6\xe0\xf9\xf25\xad>\xa1\x8e\x15\x96')
    # N'm rated "R"...
    # Duz I came back
    # Eut don't be afr

    # => keystream[0] = ciphertext[0] ^ ord('I')  (Since the first letter is obviously 'I')
    keystream[0] = transposed_blocks[0][0] ^ ord('I')

    return keystream


def decrypt_ciphertexts(ciphertexts, keystream, block_size=16):
    decrypted_ciphertexts = []
    for ct in ciphertexts:
        decrypted_ciphertext = b""
        for i in range(0, len(ct), block_size):
            cipher = ct[i:i + block_size]
            decrypted_ciphertext += xor_byte_sequences(cipher, keystream[:len(cipher)])
        decrypted_ciphertexts.append(decrypted_ciphertext)
    return decrypted_ciphertexts


def main():
    plaintexts = read_ciphertexts("CTR_break_ciphertexts_statistically.txt")
    ciphertexts = encrypt_ciphertexts(plaintexts)
    keystream = recover_keystream(ciphertexts)
    decrypted_texts = decrypt_ciphertexts(ciphertexts, keystream)

    for text in decrypted_texts:
        print(text.decode(errors='ignore'))


if __name__ == '__main__':
    main()
