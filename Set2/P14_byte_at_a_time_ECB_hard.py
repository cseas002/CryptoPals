import random
from base64 import b64decode
from P11_ECB_CBC_detection_oracle import generate_random_bytes, detect_mode
from Set1.P7_AES_ECB import aes_ecb_encrypt, aes_ecb_decrypt
# Copy your oracle function to a new function that encrypts buffers under ECB mode
# using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
from Set2.P12_byte_at_a_time_ECB_simple import detect_block_size
from Set2.P9_PKCS_7 import add_padding

# Generate a consistent random key (only once)
KEY = random.randbytes(16)

# Decoded unknown string
UNKNOWN_STRING = b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU"
    "aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v"
    "LCBJIGp1c3QgZHJvdmUgYnkK"
)

prefix = bytearray(random.randbytes(random.randint(1, 420)))


def encryption_oracle_ECB(user_input: bytearray) -> str:
    """Encrypts user input + unknown string under AES-128-ECB"""
    # What you have now is a function that produces:
    # AES-128-ECB(random-prefix || your-string || unknown-string, random-key)
    plaintext = prefix + user_input + UNKNOWN_STRING
    plaintext = add_padding(plaintext, 16)  # Add padding so the encryption does not crash
    return aes_ecb_encrypt(plaintext, KEY)


def find_unknown_str_start_index(block_size: int):
    """Function which finds the starting index of the unknown string"""
    # Initially, we will add 31 (2 * block_size - 1) 'A's and check the index of the block full of 'A's
    # This way there is only one block full of 16 A's
    a_index = 0
    a_amount = (2 * block_size - 1)
    a_bytes = bytearray(b"A" * a_amount)
    a = b"A" * block_size
    a_encrypted = aes_ecb_encrypt(a, KEY)
    encrypted_message = encryption_oracle_ECB(a_bytes)
    for i in range(0, len(encrypted_message), block_size):
        if encrypted_message[i: i + block_size] == a_encrypted:
            a_index = i
            # print(aes_ecb_decrypt(encrypted_message[i: i + block_size], KEY))  # b'AAAAAAAAAAAAAAAA'
            break

    # Now we found the block full of A's. Let's reduce the size one-by-one to find how many A's we need
    # in order to have a block full of A's except one byte

    while True:
        a_amount -= 1
        a_bytes = bytearray(b"A" * a_amount)
        encrypted_message = encryption_oracle_ECB(a_bytes)
        if encrypted_message[a_index: a_index + block_size] != a_encrypted:
            # If there is no more a full 16 byte block, then we found the right amount of A's so they fill
            # The whole block, except the last byte!
            break

    return a_index // block_size, a_amount


def byte_at_a_time_ecb_decrypt(block_size: int) -> str:
    # Initially, we haven't decrypted anything from the string, so we will add the first string's byte at the end
    # of b"AAAAAAAAAAAAAAA" (15 'A's), decrypt it, and see which letter it is, by matching it with the directory of all
    # possible letters.
    start_block_index, a_amount = find_unknown_str_start_index(block_size)
    decrypted = b""

    # For each letter of the unknown string
    for i in range(len(UNKNOWN_STRING)):
        # We start with a_prefix A's, and then we reduce 1 by one until we reach - (block_size - 1)
        # So e.g. a_amount = 18. We start from 18, then 17, ... , until 3 and then again 18
        a_prefix = bytearray(b"A" * (a_amount - (i % block_size)))

        # Initially the block index is the A's start block index, after 16 iterations it's +1 , etc.
        block_index = start_block_index + len(decrypted) // block_size

        # 4. Make a dictionary of every possible last byte by feeding different strings to the oracle;
        # for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
        block_dict = {}
        for byte in range(256):
            test_input = a_prefix + decrypted + bytes([byte])
            # Encrypt the block the input, but keep the first 16 bytes first, then the second 16 (16-31), etc.
            encrypted_block = encryption_oracle_ECB(test_input)[: (block_index + 1) * block_size]
            # Save the encryption in the dictionary (key: encrypted block, value: the byte value)
            block_dict[str(encrypted_block)] = bytes([byte])

        # 5. Match the output of the one-byte-short input to one of the entries in your dictionary.
        # You've now discovered the first byte of unknown-string.

        # 6. Repeat for the next byte.
        encrypted_output = encryption_oracle_ECB(a_prefix)[: (block_index + 1) * block_size]
        if str(encrypted_output) in block_dict:
            decrypted += block_dict[str(encrypted_output)]
        else:
            break  # Stop when no match (end of text)

    return decrypted.decode('utf-8')


def main():
    block_size = detect_block_size()
    # 2. Detect that the function is using ECB. You already know, but do this step anyways.
    mode = detect_mode(b"A" * block_size * 4)
    print(f"Block Size: {block_size}")
    print(f"Mode: {mode}")

    # 3. Knowing the block size, craft an input block that is exactly 1 byte short
    # (for instance, if the block size is 8 bytes, make "AAAAAAA").
    # Think about what the oracle function is going to put in that last byte position.
    # (answer) The oracle will append the first byte of the unknown string

    if mode == 'ECB':
        decrypted_string = byte_at_a_time_ecb_decrypt(16)
        print(decrypted_string)


if __name__ == "__main__":
    main()
