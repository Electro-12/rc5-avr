# RC5 Block Cipher - AVR Assembly (ATmega32)

A from-scratch implementation of the RC5 block cipher (Rivest, 1994), written
in AVR assembly for an ATmega32 microcontroller. Implements key expansion,
encryption, and decryption directly on the hardware - no crypto library, no C.

**Parameters:** RC5-16/8/12 (16-bit words, 8 rounds, 12-byte / 96-bit key)

## Files

- `RC5_AVR.asm` - the implementation. Written for Microchip Studio.
- `reference/rc5_reference.py` - an independent Python re-implementation of the
  same algorithm, used to verify the AVR code produces the correct output
  (see below).

## How it works

- `KEY_EXPANSION` - unpacks the 12-byte key into 6 words (`L[]`), initializes
  the expanded key table `S[0..17]` from the RC5 magic constants `P16`/`Q16`,
  then runs the standard 3-pass mixing loop.
- `ENCRYPT` / `DECRYPT` - the standard RC5 Feistel-like round function, using
  data-dependent rotations (`ROL16V`/`ROR16V` helper routines, since AVR has
  no native variable-shift instruction).
- `MAIN` loads a test key and plaintext into SRAM, runs key expansion, then
  encryption, and halts.

Memory layout:

| Label | Address | Contents |
|---|---|---|
| `K_ADDR` | 0x0100 | 12-byte secret key |
| `L_ADDR` | 0x0110 | 6 key words (post key-packing) |
| `S_ADDR` | 0x0120 | 18-word expanded key table |
| `A_ADDR` | 0x0150 | 16-bit A (plaintext in / ciphertext out) |
| `B_ADDR` | 0x0152 | 16-bit B (plaintext in / ciphertext out) |

## Verifying it's correct

`MAIN` hardcodes a test key and plaintext:

- Key: `00 01 02 03 04 05 06 07 08 09 0A 0B`
- Plaintext: `A0 = 0x0001`, `B0 = 0x0002`

Running `reference/rc5_reference.py` (a plain-Python RC5-16/8/12
implementation, independent of the AVR code) on the same key and plaintext
gives:

```
Ciphertext: Ar=58AC  Br=21C4
```

To check the AVR implementation against this:

1. Open `RC5_AVR.asm` in Microchip Studio and start the simulator.
2. Run until it hits the `DONE:` infinite loop.
3. Open the memory viewer and check SRAM at `0x0150`-`0x0153`.
4. Expect: `AC 58 C4 21` (little-endian: `A_ADDR` = `58AC`, `B_ADDR` = `21C4`).

If those match, the key expansion and encryption round logic are correct.

I've also confirmed the source assembles cleanly with no errors (checked with
`avra`, a third-party AVR assembler, as an independent syntax check outside
Microchip Studio).

## Notes / possible extensions

- `DECRYPT` is implemented but not called from `MAIN` by default - uncomment
  the `rcall DECRYPT` line to round-trip the ciphertext back to the original
  plaintext as a further correctness check.
- No UART output - results currently have to be read from SRAM in the
  simulator. Adding UART output of the ciphertext bytes would make this
  runnable on real hardware without a debugger attached.
- Only the fixed test key/plaintext hardcoded in `MAIN` is exercised; there's
  no test harness sweeping multiple key/plaintext pairs against the reference
  implementation.
