class MT19937:
    w, n = 32, 624
    f = 1812433253
    m, r = 397, 31
    a = 0x9908B0DF
    b, c = 0x9D2C5680, 0xEFC60000
    u, s, t, l = 11, 7, 15, 18

    def __init__(self, seed):
        self.state_array = [0] * MT19937.n
        self.cnt = 0
        self.initialize(seed)

    def initialize(self, seed):
        self.state_array[0] = seed
        for i in range(1, MT19937.n):
            self.state_array[i] = (MT19937.f * (self.state_array[i - 1] ^ (self.state_array[i - 1] >> (MT19937.w - 2))) + i) & ((1 << MT19937.w) - 1)
        self.twist()

    def twist(self):
        for i in range(MT19937.n):
            lower_mask = (1 << MT19937.r) - 1
            upper_mask = (~lower_mask) & ((1 << MT19937.w) - 1)
            tmp = (self.state_array[i] & upper_mask) + (self.state_array[(i + 1) % MT19937.n] & lower_mask)
            tmpA = tmp >> 1
            if (tmp % 2):
                tmpA = tmpA ^ MT19937.a
            self.state_array[i] = self.state_array[(i + MT19937.m) % MT19937.n] ^ tmpA
        self.cnt = 0

    def temper(self):
        if self.cnt == MT19937.n:  # or n % cnt, but cnt is reset to 0 in every twist()
            self.twist()
        y = self.state_array[self.cnt]
        y ^= (y >> MT19937.u)
        y ^= ((y << MT19937.s) & MT19937.b)
        y ^= ((y << MT19937.t) & MT19937.c)
        y ^= (y >> MT19937.l)
        self.cnt += 1
        return y & ((1 << MT19937.w) - 1)


def main():
    rng = MT19937(42)
    for _ in range(10):
        print(rng.temper())


if __name__ == '__main__':
    main()
