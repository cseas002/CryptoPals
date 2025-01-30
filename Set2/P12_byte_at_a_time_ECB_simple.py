import random
from base64 import b64decode
from P11_ECB_CBC_detection_oracle import generate_random_bytes, detect_mode
from Set1.P7_AES_ECB import aes_ecb_encrypt
# Copy your oracle function to a new function that encrypts buffers under ECB mode
# using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
from Set2.P9_PKCS_7 import add_padding

# Generate a consistent random key (only once)
KEY = random.randbytes(16)

# Decoded unknown string
UNKNOWN_STRING = b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpU"
    "aGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5v"
    "LCBJIGp1c3QgZHJvdmUgYnkK"
)


def encryption_oracle_ECB(user_input: bytearray) -> str:
    """Encrypts user input + unknown string under AES-128-ECB"""
    # What you have now is a function that produces:
    # AES-128-ECB(your-string || unknown-string, random-key)
    plaintext = user_input + UNKNOWN_STRING
    plaintext = add_padding(plaintext, 16)  # Add padding so the encryption does not crash
    return aes_ecb_encrypt(plaintext, KEY)


def byte_at_a_time_ecb_decrypt(block_size: int) -> str:
    # Initially, we haven't decrypted anything from the string, so we will add the first string's byte at the end
    # of b"AAAAAAAAAAAAAAA" (15 'A's), decrypt it, and see which letter it is, by matching it with the directory of all
    # possible letters.
    decrypted = b""

    # For each letter of the unknown string
    for i in range(len(UNKNOWN_STRING)):
        # We will have b"A" * i % 16 - 1 times as our "decrypted" message
        prefix = bytearray(b"A" * ((block_size - i - 1) % block_size))  # Initially 15, then 14, ... 0, and again 15, 14
        # (-1 % 16 = 15)
        block_index = len(decrypted) // block_size  # Initially the block index is 0, after 16 iterations it's 1, etc.

        # 4. Make a dictionary of every possible last byte by feeding different strings to the oracle;
        # for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
        block_dict = {}
        for byte in range(256):
            test_input = prefix + decrypted + bytes([byte])
            # Encrypt the block the input, but keep the first 16 bytes first, then the second 16 (16-31), etc.
            encrypted_block = encryption_oracle_ECB(test_input)[: (block_index + 1) * block_size]
            # Save the encryption in the dictionary (key: encrypted block, value: the byte value)
            block_dict[str(encrypted_block)] = bytes([byte])

        # 5. Match the output of the one-byte-short input to one of the entries in your dictionary.
        # You've now discovered the first byte of unknown-string.

        # 6. Repeat for the next byte.
        encrypted_output = encryption_oracle_ECB(prefix)[: (block_index + 1) * block_size]
        if str(encrypted_output) in block_dict:
            decrypted += block_dict[str(encrypted_output)]
        else:
            break  # Stop when no match (end of text)

    return decrypted.decode('utf-8')


def detect_block_size() -> int:
    # 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
    # then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
    for i in range(1, 65):  # Test up to 64 bytes
        try:
            aes_ecb_encrypt(b"A" * i, KEY)
            return i
        except:
            continue
            # print(i, " is not the size of the block")
    return -1  # Error case (should never hit)


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
