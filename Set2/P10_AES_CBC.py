import sys
from base64 import b64decode

# Add the parent directory to sys.path
from Set1.P7_AES_ECB import aes_encrypt_block, aes_decrypt_block
from Set1.P2_Fixed_XOR import xor_byte_sequences
from Set2.P15_PKCS_7_padding_validation import check_padding


def aes_cbc(data: bytes, key: bytes, iv: bytes, encrypt: bool, block_size=16):
    """
    Encrypt or decrypt data in CBC mode manually by processing block-by-block.
    Args:
    - data (bytes): The plaintext or ciphertext.
    - key (bytes): The 16-byte AES key.
    - iv (bytes): The 16-byte initialization vector (IV).
    - encrypt (bool): True for encryption, False for decryption.
    Returns:
    - plaintext (bytes): The resulting ciphertext or plaintext.
    """
    plaintext = b""
    previous_block = iv

    for i in range(0, len(data), block_size):
        current_block = data[i:i + block_size]

        if encrypt:
            # XOR plaintext with the previous ciphertext block (or IV for the first block)
            xor_result = xor_byte_sequences(current_block, previous_block)
            # Encrypt the XORed block
            encrypted_block = aes_encrypt_block(xor_result, key)
            # Append the encrypted block to the plaintext
            plaintext += encrypted_block
            # Update the previous block for the next iteration
            previous_block = encrypted_block
        else:
            # Decrypt the current ciphertext block
            decrypted_block = aes_decrypt_block(current_block, key)
            # XOR the decrypted block with the previous ciphertext block (or IV for the first block)
            xor_result = xor_byte_sequences(decrypted_block, previous_block)
            # Append the XORed block (plaintext) to the plaintext
            plaintext += xor_result
            # Update the previous block for the next iteration
            previous_block = current_block

            # If it's the last block, check for padding
            if i == len(data) - block_size:
                # Remove padding
                padding = plaintext[len(plaintext) - 1]
                if check_padding(plaintext):
                    plaintext = plaintext[0:len(plaintext) - padding]

    return plaintext


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes):
    return aes_cbc(data, key, iv, True)


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes):
    return aes_cbc(data, key, iv, False)


def main():
    if len(sys.argv) == 1:
        filename = "AES-base64-encrypted-file-CBC.txt"
    elif len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <base64_file>")
        exit()
        filename = ""  # not needed
    else:
        filename = sys.argv[1]

    # Define the key
    key = b"YELLOW SUBMARINE"  # 16 bytes long key

    # Read the base64-encoded ciphertext from the input file
    with open(filename, "r") as file:
        base64_ciphertext = file.read()

    # Decode the Base64-encoded content to raw bytes
    ciphertext = b64decode(base64_ciphertext)

    iv = b"\x00" * 16  # Initialization vector (IV)

    # Decrypt the ciphertext manually in ECB mode
    plaintext = aes_cbc(ciphertext, key, iv, False)

    # Print the decrypted plaintext
    print(f"Decrypted Message:\n{plaintext.decode('utf-8', errors='ignore')}")


if __name__ == '__main__':
    main()
