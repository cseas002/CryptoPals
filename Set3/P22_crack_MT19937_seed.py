import time
import random

from Set3.P21_MT19937 import MT19937


def generate_rng_output():
    """Simulates waiting, seeds RNG with current timestamp, then returns first output."""
    time.sleep(random.randint(40, 100))  # Wait a random time (simulate delay)

    seed = int(time.time())  # Get current Unix timestamp as seed
    rng = MT19937(seed)  # Seed RNG
    time.sleep(random.randint(40, 100))  # Wait again (simulate delay)

    first_output = rng.temper()

    return seed, first_output


def crack_mt19937_seed(output, time_window=200):
    """Brute-forces the seed by checking recent timestamps."""
    current_time = int(time.time())

    for possible_seed in range(current_time, current_time - time_window, -1):
        rng = MT19937(possible_seed)
        if rng.temper() == output:
            return possible_seed

    return None  # If we fail to find a match


def main():
    actual_seed, rng_output = generate_rng_output()
    print(f"Actual Seed: {actual_seed}")
    print(f"RNG Output: {rng_output}")

    # Try to find the seed
    guessed_seed = crack_mt19937_seed(rng_output)
    print(f"Guessed Seed: {guessed_seed}")

    if guessed_seed == actual_seed:
        print("Successfully cracked the seed!")
    else:
        print("Failed to crack the seed.")


if __name__ == '__main__':
    main()
