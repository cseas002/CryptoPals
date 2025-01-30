import re
import random

# Generate a consistent random AES key (once)
from Set1.P7_AES_ECB import aes_ecb_encrypt, aes_ecb_decrypt
from Set2.P9_PKCS_7 import add_padding

KEY = random.randbytes(16)


def parse_kv(s: str) -> dict:
    """Parses a key-value string into a dictionary."""
    dictionary = {}
    # s = s.split('\0')[0]
    print(s.split('&'))
    for pair in s.split("&"):
        pair_array = pair.split('=')
        dictionary[pair_array[0]] = pair_array[1]
    return dictionary


def profile_for(email: str) -> str:
    """Encodes a user profile, sanitizing the email to prevent injection attacks."""
    email = re.sub(r"[&=]", "", email)  # Remove metacharacters
    profile = f"email={email}&uid=10&role=user"
    return profile


def encrypt_profile(email: str) -> bytes:
    """Encrypts a user profile under AES-128-ECB."""
    profile = profile_for(email)
    profile = bytearray(profile.encode('ascii'))
    add_padding(profile, 16)
    return aes_ecb_encrypt(profile, KEY)


def decrypt_profile(ciphertext: bytes) -> dict:
    """Decrypts and parses an AES-128-ECB encrypted profile."""
    plaintext = aes_ecb_decrypt(ciphertext, KEY)
    print(plaintext, "AAAAA")
    return parse_kv(plaintext.decode())


def create_admin_profile():
    """Performs ECB cut-and-paste attack to escalate privileges to admin."""
    block_size = 16

    # Step 1: Get a normal encrypted profile
    normal_ciphertext = encrypt_profile("evil@evil.com")

    # Step 2: Craft an input where "admin" is perfectly aligned in its own block (2nd)
    crafted_email = "A" * (block_size - len("email=")) + "admin" + '           '
    crafted_ciphertext = encrypt_profile(crafted_email)

    # Step 3: Extract the "admin" block
    admin_block_index = block_size  # = (len(crafted_email) - len("admin")) // block_size - 1
    admin_block = crafted_ciphertext[admin_block_index: admin_block_index + block_size]

    # Step 4: Replace the last block of normal ciphertext with admin block
    hacked_ciphertext = normal_ciphertext[0:len(normal_ciphertext) - block_size] + admin_block

    return decrypt_profile(hacked_ciphertext)


def main():
    create_admin_profile()


if __name__ == "__main__":
    main()
