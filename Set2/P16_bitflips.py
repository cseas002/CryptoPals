import random

# Generate a consistent random AES key (once)
from Set2.P10_AES_CBC import aes_cbc_encrypt, aes_cbc_decrypt
from Set2.P9_PKCS_7 import add_padding

KEY = random.randbytes(16)
IV = random.randbytes(16)


def sanitize_input(userdata: str) -> str:
    """Escape `;` and `=` in user input to prevent direct injection."""
    return userdata.replace(";", "").replace("=", "")


def encrypt_userdata(userdata: str, block_size) -> bytes:
    """Encrypts user-controlled data with a fixed prefix and suffix under AES-CBC."""
    userdata = sanitize_input(userdata)

    plaintext = (
            "comment1=cooking%20MCs;userdata=" + userdata +
            ";comment2=%20like%20a%20pound%20of%20bacon"
    )
    plaintext = add_padding(plaintext.encode(), block_size)
    ciphertext = aes_cbc_encrypt(plaintext, KEY, IV)

    return ciphertext


def decrypt_and_check_admin(ciphertext: bytes) -> bool:
    """Decrypts ciphertext and checks if the user has admin privileges."""
    plaintext = aes_cbc_decrypt(ciphertext, KEY, IV)

    print("[Decrypted Plaintext]:", plaintext)  # Debugging purpose
    return b";admin=true;" in plaintext


def bitflip_attack():
    """Modify the ciphertext to inject `;admin=true;` without knowing the key."""
    block_size = 16
    original_ciphertext = encrypt_userdata("A" * block_size, block_size)

    # Convert ciphertext to mutable bytearray
    modified_ciphertext = bytearray(original_ciphertext)

    # Find the index where user-controlled input starts
    start_index = len("comment1=cooking%20MCs;userdata=")

    # What we want to inject: ";admin=true;"
    target_text = ";admin=true;"
    attack_bytes = bytearray(target_text.encode())

    # Modify the previous block to cause bit flips
    # The block is 16 A's. Therefore, if we XOR the PREVIOUS one with 16 A's we will get 16 0s
    # (we can see it with modified_ciphertext[start_index - block_size + i] ^= ord("A"))
    # So we will XOR it again with the input we want. Remember, 0 XOR something = something (0 ^ a = a)
    for i in range(len(attack_bytes)):
        modified_ciphertext[start_index - block_size + i] ^= ord("A") ^ ord(target_text[i])

    # Send modified ciphertext to check if we gained admin access
    return decrypt_and_check_admin(bytes(modified_ciphertext))


# Run the attack
if __name__ == "__main__":
    success = bitflip_attack()
    print("Admin access granted?", success)
