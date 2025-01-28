import sys


def xor_bytes(b1: int, b2: int):
    # XOR each byte manually, bit by bit
    result = 0
    for i in range(8):
        last_bit1 = b1 & 1
        last_bit2 = b2 & 1
        # The xor result is basically 1 if the bits are different
        result_bit = 1 if last_bit1 != last_bit2 else 0
        b1 = b1 >> 1
        b2 = b2 >> 1
        # We will add to the result that bit, shifted i times
        result += result_bit << i
    return result


def xor_byte_sequences(byte_seq1: bytes, byte_seq2: bytes):
    """
    Perform XOR operation on two byte sequences of the same length.
    Args:
    - byte_seq1 (bytes): The first byte sequence.
    - byte_seq2 (bytes): The second byte sequence.

    Returns:
    - bytes: Result of XOR operation.
    """
    if len(byte_seq1) != len(byte_seq2):
        raise ValueError("The byte sequences must have the same length")

    return bytes([xor_bytes(b1, b2) for b1, b2 in zip(byte_seq1, byte_seq2)])


def hex_to_bytes(hex_string):
    """Convert a hexadecimal string to a byte sequence."""
    return bytes.fromhex(hex_string)


def bytes_to_hex(byte_seq):
    """Convert a byte sequence to a hexadecimal string."""
    return byte_seq.hex()


def main():
    if len(sys.argv) != 3:
        # Provide default values if no arguments are passed
        hex_string_1 = "1c0111001f010100061a024b53535009181c"
        hex_string_2 = "686974207468652062756c6c277320657965"
    else:
        hex_string_1 = sys.argv[1]
        hex_string_2 = sys.argv[2]

    # Convert hex strings to bytes
    byte_seq1 = hex_to_bytes(hex_string_1)
    byte_seq2 = hex_to_bytes(hex_string_2)

    # Perform XOR on the byte sequences
    xor_result = xor_byte_sequences(byte_seq1, byte_seq2)

    # Convert the result back to a hexadecimal string
    result_hex = bytes_to_hex(xor_result)

    print(result_hex)


if __name__ == '__main__':
    main()
