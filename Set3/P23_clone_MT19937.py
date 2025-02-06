from Set3.P21_MT19937 import MT19937

OUTPUTS = 624  # Number of state variables in MT19937


def untemper(y):
    """Reverse the tempering function to recover the original state value."""

    # Original tempering steps:

    # if self.cnt == MT19937.n:
    #     self.twist()
    # y = self.X[self.cnt]
    # y = y ^ ((y >> MT19937.u) & MT19937.d)
    # y = y ^ ((y << MT19937.s) & MT19937.b)
    # y = y ^ ((y << MT19937.t) & MT19937.c)
    # y = y ^ (y >> MT19937.l)
    # self.cnt += 1
    # return y & ((1 << MT19937.w) - 1)

    # Step 1: Reverse y = y ^ (y >> l)
    # Since l = 18, we can directly recover the top 14 bits of y.
    # We then recover the rest by XORing iteratively.
    y ^= (y >> MT19937.l)

    # Step 2: Reverse y = y ^ ((y << t) & c)
    # - t = 15
    # - c = 0xEFC60000 (1110 1111 1100 0110 0000 0000 0000 0000 in binary)
    # - The lowest 16 bits of c are 0, so the last 16 bits of y' remain unchanged.
    # - We can restore y using a single left XOR operation.
    y ^= (y << MT19937.t) & MT19937.c

    # Step 3: Reverse y = y ^ ((y << s) & b)
    # - s = 7, b = 0x9D2C5680
    # - This transformation affects nearly all bits, so we must recover them iteratively.
    # - We apply the XOR shift s times to fully restore y.
    for _ in range(MT19937.s):  # Iteratively reverse bits
        y ^= (y << MT19937.s) & MT19937.b

    # y_prev = y
    # for i in range(1, 5):
    #     y ^= (y << (MT19937.s * i)) & MT19937.b
    #
    # y = y ^ (y_prev & 0xF0000000)

    # Step 4: Reverse y = y ^ (y >> u)
    # - u = 11
    # - A single right XOR only partially restores y.
    # - A second XOR with (2 * u) fills in the remaining bits. (See notes!)
    # The first 22 bits are ok because the first 11 do not change, the second 11 are xor'd twice,
    # the others are y[2*u + i] ^ y[u + i] ^ y[u + i] ^ y[i] = y[2*u + i] ^ y[i] so we just xor with y[2*u + i]!
    y ^= (y >> MT19937.u)
    y ^= y >> (2 * MT19937.u)  # Ensures full bit recovery

    return y


def clone_mt19937(original_rng, seed=42):
    """Clone an MT19937 generator by recovering its internal state."""
    cloned_state = [untemper(original_rng.temper()) for _ in range(OUTPUTS)]

    # Create a new instance with the same seed
    cloned_rng = MT19937(seed)
    cloned_rng.state_array = cloned_state  # Overwrite state with recovered values

    return cloned_rng


def main():
    seed = 42
    original_rng = MT19937(seed)

    print("Generating first 10 outputs from the original RNG:")
    original_outputs = [original_rng.temper() for _ in range(10)]
    print(original_outputs)

    # Clone the RNG
    cloned_rng = clone_mt19937(MT19937(seed))

    print("\nGenerating first 10 outputs from the cloned RNG:")
    cloned_outputs = [cloned_rng.temper() for _ in range(10)]
    print(cloned_outputs)

    # Check if both sequences match
    assert original_outputs == cloned_outputs, "Cloned RNG does not match the original!"
    print("\nSuccessfully cloned the MT19937 generator!")


if __name__ == "__main__":
    main()
