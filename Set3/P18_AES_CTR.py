from base64 import b64decode
from Set1.P2_Fixed_XOR import xor_byte_sequences
from Set1.P7_AES_ECB import aes_encrypt_block


def increment_nonce(nonce):
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes long")

    # Increment only the last 8 bytes (counter part)
    counter_int = int.from_bytes(nonce[8:], byteorder="little") + 1
    new_counter = counter_int.to_bytes(8, byteorder="little")

    return nonce[:8] + new_counter  # Keep the first 8 bytes (nonce) unchanged


def aes_ctr(plaintext, key, nonce=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            block_size=16, fixed_once=False):
    result = b""
    for i in range(0, len(plaintext), block_size):
        keystream = aes_encrypt_block(nonce, key)  # Generate keystream block
        block = plaintext[i:i + block_size]  # Slice plaintext into 16-byte chunks
        result += xor_byte_sequences(block, keystream[:len(block)])  # XOR with keystream
        if not fixed_once:
            nonce = increment_nonce(nonce)  # Increment counter

    return result


def main():
    message = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = b"YELLOW SUBMARINE"
    # message = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    print(aes_ctr(message, key))


if __name__ == '__main__':
    main()
