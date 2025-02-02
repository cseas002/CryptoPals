import random
from base64 import b64decode
from Set1.P2_Fixed_XOR import xor_byte_sequences
from Set2.P10_AES_CBC import aes_cbc_encrypt, aes_cbc_decrypt
from Set2.P9_PKCS_7 import add_padding

KEY = random.randbytes(16)

# List of base64-encoded plaintexts
PLAINTEXTS = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]


# The second function should consume the ciphertext produced by the first function, decrypt it, check its padding,
# and return true or false depending on whether the padding is valid.
def valid_padding_oracle(ciphertext, iv) -> bool:
    """
    :param ciphertext: ciphertext to decrypt
    :param iv: the IV, OR the previous block (if we want to decrypt one block)
    :return: True if padding is correct, false otherwise
    """
    try:
        aes_cbc_decrypt(ciphertext, KEY, iv, check_padding_is_valid=True)
        return True
    except:
        return False


def encrypt_cbc(block_size: int):
    """Encrypts a randomly chosen string with AES-128-CBC and returns (ciphertext, IV)."""
    # Select a random plaintext, decode from base64
    plaintext = b64decode(random.choice(PLAINTEXTS))

    # Add padding
    plaintext = add_padding(plaintext, block_size)

    iv = random.randbytes(16)

    # Encrypt with CBC
    ciphertext = aes_cbc_encrypt(plaintext, KEY, iv)

    return ciphertext, iv


def decrypt_block(current_block, prev_block, block_size):
    """
    This function decrypts the current CBC block based on its previous block
    :param current_block: Current CBC block to be decrypted
    :param prev_block: Previous block, in which we will modify byte-by-byte starting from the last
    :param block_size: The block size (16)
    :return: the decrypted block and the recovered plaintext (which is basically current decrypted block XOR'd with previous)
    """
    decrypted_block = bytearray(block_size)  # Stores the decrypted bytes

    for byte_index in range(1, block_size + 1):  # Decrypting from last byte to first (we use -byte_index)
        modified_prev = bytearray(prev_block)

        for i in range(1, byte_index):  # Adjust previously decrypted bytes
            # After decrypting last byte, we want the last Plaintext byte (from modified ciphertext) to be 0x02
            modified_prev[-i] = decrypted_block[-i] ^ byte_index

        # Brute-force the current byte
        for guess in range(256):
            modified_prev[-byte_index] = guess  # Try modifying the last (unknown) byte

            # modified_ciphertext = modified_prev + current_block
            # We test whether the decryption of the current block is valid, assuming only two blocks: current and previous
            if valid_padding_oracle(current_block, modified_prev):
                decrypted_block[-byte_index] = guess ^ byte_index
                break  # Found the correct byte
    recovered_plaintext = bytearray(xor_byte_sequences(prev_block, decrypted_block))
    return decrypted_block, recovered_plaintext


def padding_oracle_attack(ciphertext, iv, block_size=16):
    """Performs a Padding Oracle Attack to recover the plaintext.

    We will start by decrypting the second to last block by changing firstly the last byte
    We know that valid PKCS#7 padding means the last byte is \x01.

    e.g.:
    Ciphertext: C0 | C1
    Modify the last byte of C0:
    We modify C0[15] byte-by-byte and send (C0' | C1) for decryption.

    Change C0[15] to 0x00, 0x01, 0x02 ... 0xFF
    If padding is invalid, try the next byte.
    If padding is valid, then P1'[15] must be \x01 because it's the correct padding.

    Let’s say at C0[15] = 0xAB, the oracle returns "valid padding" (True).
        D_k(C1)[15] XOR C0'[15] = 0x01
    =>  D_k(C1)[15] = 0xAB XOR 0x01
    =>  P1[15] = D_k(C1)[15] XOR C0[15] (the original C0[15])

    Since we know C0[15] from the original intercepted ciphertext, we get P1[15]!

    Now we move to P1[14]
    For valid padding (\x02\x02), we need P1'[15] = 0x02 (the recovered plaintext from the modified ciphertext)
    P1[15] = D_k(C1)[15] XOR C0[15]
    So we set C0''[15] = D_k(C1)[15] XOR 0x02

    We will then do the same for C0[13] (with 0x03), etc.
    """
    num_blocks = len(ciphertext) // block_size  # (It has to be a multiple of <block_size>)
    recovered_plaintext = bytearray(len(ciphertext))

    # Starting from the last block, until the first block
    for block_index in range(num_blocks - 1, -1, -1):
        if block_index == 0:
            prev_block = iv  # The IV is used for the first block
        else:
            prev_block = ciphertext[(block_index - 1) * block_size:block_index * block_size]

        current_block = ciphertext[block_index * block_size:(block_index + 1) * block_size]

        recovered_plaintext[block_index * block_size:(block_index + 1) * block_size] = \
            decrypt_block(current_block, prev_block, block_size)[1]

    return recovered_plaintext


def main():
    ciphertext, iv = encrypt_cbc(16)

    print(padding_oracle_attack(ciphertext, iv))
    print("Original decrypted:", aes_cbc_decrypt(ciphertext, KEY, iv))


if __name__ == '__main__':
    main()
