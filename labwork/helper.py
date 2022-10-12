def multiply_with_alpha_in_gf2_128(x):
    # a^128 = a^7 + a^2 + a + 1
    return (x << 1) ^ (0x87 if (x & (0b1 << 128)) else 0)