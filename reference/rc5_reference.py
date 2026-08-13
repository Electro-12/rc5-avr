"""
Reference RC5-16/8/12 encryption, used to cross-check RC5_AVR.asm.

This is a plain-Python re-implementation of the RC5 algorithm (Rivest 1994)
with the same parameters as the AVR code (w=16, r=8, b=12), used only to
compute a known-correct ciphertext for the test key/plaintext hardcoded in
MAIN. See ../README.md for how to use this to verify RC5_AVR.asm.
"""


W = 16
R = 8
MASK = (1 << W) - 1
P16 = 0xB7E1
Q16 = 0x9E37
T = 2 * (R + 1)  # 18
C = 6            # key words (b=12 bytes / 2)

def rotl(x, n, bits=W):
    n %= bits
    return ((x << n) | (x >> (bits - n))) & MASK

def key_expand(key_bytes):
    L = [0] * C
    for i in range(C):
        L[i] = key_bytes[2*i] | (key_bytes[2*i+1] << 8)

    S = [0] * T
    S[0] = P16
    for i in range(1, T):
        S[i] = (S[i-1] + Q16) & MASK

    A = B = i = j = 0
    for _ in range(3 * max(T, C)):
        A = S[i] = rotl((S[i] + A + B) & MASK, 3)
        B = L[j] = rotl((L[j] + A + B) & MASK, (A + B) & 0x0F)
        i = (i + 1) % T
        j = (j + 1) % C
    return S

def encrypt(A0, B0, S):
    A = (A0 + S[0]) & MASK
    B = (B0 + S[1]) & MASK
    for i in range(1, R + 1):
        A = (rotl(A ^ B, B & 0x0F) + S[2*i]) & MASK
        B = (rotl(B ^ A, A & 0x0F) + S[2*i+1]) & MASK
    return A, B

key = list(range(12))  # 00 01 02 ... 0B, matches the test key in RC5_AVR.asm
S = key_expand(key)
A0, B0 = 0x0001, 0x0002  # matches MAIN's hardcoded plaintext
Ar, Br = encrypt(A0, B0, S)

print(f"Key: {' '.join(f'{b:02X}' for b in key)}")
print(f"Plaintext:  A0={A0:04X}  B0={B0:04X}")
print(f"Ciphertext: Ar={Ar:04X}  Br={Br:04X}")
print()
print("RC5_AVR.asm writes the result back in place at A_ADDR/B_ADDR (0x0150/0x0152):")
print(f"  A_ADDR (0x0150-0x0151) -> low={Ar & 0xFF:02X} high={(Ar>>8) & 0xFF:02X}")
print(f"  B_ADDR (0x0152-0x0153) -> low={Br & 0xFF:02X} high={(Br>>8) & 0xFF:02X}")
