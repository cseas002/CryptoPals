import sys


# Function to initialize the character set for Base64 encoding
def initialize_character_set():
    character_set = []
    # Add 'A'-'Z' (uppercase alphabet) to the character set
    for i in range(26):
        character_set.append(chr(ord('A') + i))

    # Add 'a'-'z' (lowercase alphabet) to the character set
    for i in range(26):
        character_set.append(chr(ord('a') + i))

    # Add '0'-'9' (digits) to the character set
    for i in range(10):
        character_set.append(str(i))

    # Add '+' and '/' to complete the Base64 character set
    character_set.append('+')
    character_set.append('/')

    return character_set  # Return the complete Base64 character set


# Function to convert a hex string into a Base64 encoded string
def hex_to_base_64(hex_string):
    # Convert the hex string into a binary string
    binary_string = ""
    for char in hex_string:
        # https://stackoverflow.com/questions/1425493/convert-hex-to-binary
        # Convert each hex character to its integer value
        hex_value = int(char, 16)
        # Convert the integer value to a 4-bit binary string (padded with zeros if needed)
        binary_value = bin(hex_value)[2::].zfill(4)
        # Append the binary string representation to the final binary string
        binary_string += binary_value

    # Pad the binary string with 0s to make its length a multiple of 6
    # If the length is already divisible by 6, no padding is added
    for padding in range((6 - len(binary_string) % 6) % 6):
        binary_string += "0"

    # Initialize the Base64 encoded string
    base_64_string = ""
    # Get the Base64 character set
    character_set = initialize_character_set()

    # Divide the binary string into 6-bit chunks and convert each to Base64
    for base_64_char_index in range(0, len(binary_string), 6):
        # Get the value of the current 6-bit chunk
        base_64_value = int(binary_string[base_64_char_index:base_64_char_index + 6], 2)
        # Use the value as an index to find the corresponding Base64 character
        base_64_char = character_set[base_64_value]
        # Append the Base64 character to the result string
        base_64_string += base_64_char

    return base_64_string  # Return the final Base64 encoded string


# Main function to handle command-line arguments and execute the conversion
def main():
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 2:
        print(f"Correct format: python {sys.argv[0]} <hex to be converted to base64>")
        exit()

    # Get the hex string from command-line arguments
    hex_string = sys.argv[1]

    # Perform the hex-to-Base64 conversion
    base_64_string = hex_to_base_64(hex_string)

    # Print the resulting Base64 encoded string
    print(base_64_string)


# Entry point of the script
if __name__ == '__main__':
    main()
