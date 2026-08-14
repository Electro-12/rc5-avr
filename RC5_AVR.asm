; ============================================================
; RC5 Implementation in AVR Assembly (ATmega32 / Microchip Studio)
; Parameters:
;   - Word size (w)  = 16 bits
;   - Rounds (r)     = 8
;   - Key size (b)   = 12 bytes
;   - Key words (c)  = 6
;   - Table size (t) = 18  (S[0]..S[17])
;   - P16            = 0xB7E1
;   - Q16            = 0x9E37
;   - Iterations     = 54  (3 * max(18,6))
;
; Changelog (v2 - fixed):
;   - .equ lines used commas, AVR assembler wants '='. This is what
;     was breaking the build - every single constant line failed.
;   - Bigger issue: in a few spots the S[] byte offset was being
;     computed straight into r26. Problem is r26 IS XL (low byte of
;     the X pointer), so as soon as you do "ldi XL, LOW(S_ADDR)" it
;     stomps whatever offset you just put there, and "add XL, r26"
;     ends up adding XL to itself instead of to the offset. Address
;     math goes completely wrong, encryption runs but produces
;     garbage. No assembler error for this one, just wrong output.
;     Moved the offset calc to a scratch reg that isn't part of any
;     pointer pair (r19, mostly) and compute it BEFORE loading the
;     pointer.
;   - Brought DECRYPT back and fixed the same bug in it (it hadn't
;     been touched/tested before so it still had the old pattern).
;   - Added a small self-check at the end: encrypt, then decrypt,
;     then compare against the plaintext we started with. Writes
;     0x01 to STATUS_ADDR if they match, 0x00 if they don't. Beats
;     eyeballing register values in the simulator every time.
;
; Register usage:
;   R0:R1   - temp / mul result (r1 assumed 0, AVR convention)
;   R16:R17 - general temp
;   R18:R19 - loop counters / index scratch
;   R20:R21 - A (low:high)
;   R22:R23 - B (low:high)
;   R24:R25 - rotate input/output, misc temp
;   R26:R27 - X pointer (S[] array)
;   R28:R29 - Y pointer (L[] array)
;   R30:R31 - Z pointer (K[] array)
;
; Memory map (SRAM):
;   0x0100 - 0x010B : K[0..11]     secret key, 12 bytes
;   0x0110 - 0x011B : L[0..5]      key words, 6 * 2 bytes
;   0x0120 - 0x0143 : S[0..17]     expanded key table, 18 * 2 bytes
;   0x0150 - 0x0151 : A            plaintext in / working value
;   0x0152 - 0x0153 : B            plaintext in / working value
;   0x0154 - 0x0155 : CT_A         ciphertext snapshot after ENCRYPT
;   0x0156 - 0x0157 : CT_B         ciphertext snapshot after ENCRYPT
;   0x0160 - 0x0161 : A0_SAVE      original A0, kept for the self-check
;   0x0162 - 0x0163 : B0_SAVE      original B0, kept for the self-check
;   0x0164          : STATUS       0x01 = round-trip ok, 0x00 = mismatch
; ============================================================

.include "m32def.inc"

; ---- Constants ----
.equ P16 = 0xB7E1
.equ Q16 = 0x9E37
.equ ROUNDS = 8
.equ T_SIZE = 18              ; 2*(r+1)
.equ C_SIZE = 6               ; key words
.equ B_SIZE = 12              ; key bytes
.equ ITER = 54                ; 3*18

; ---- SRAM addresses ----
.equ K_ADDR = 0x0100
.equ L_ADDR = 0x0110
.equ S_ADDR = 0x0120
.equ A_ADDR = 0x0150
.equ B_ADDR = 0x0152
.equ CT_A_ADDR = 0x0154
.equ CT_B_ADDR = 0x0156
.equ A0_SAVE = 0x0160
.equ B0_SAVE = 0x0162
.equ STATUS_ADDR = 0x0164

; ============================================================
.cseg
.org 0x0000
    rjmp    MAIN

; ============================================================
; MAIN
; ============================================================
MAIN:
    ldi     r16, HIGH(RAMEND)
    out     SPH, r16
    ldi     r16, LOW(RAMEND)
    out     SPL, r16

    ; test key - all zero bytes, swap this for a real key when you're
    ; done bring-up testing
    ldi     ZL, LOW(K_ADDR)
    ldi     ZH, HIGH(K_ADDR)
    ldi     r16, 0x00
    ldi     r17, 0x0C          ; 12 bytes
LOAD_KEY:
    st      Z+, r16
    inc     r16
    dec     r17
    brne    LOAD_KEY

    ; test plaintext: A0 = 0x0001, B0 = 0x0002
    ldi     r16, 0x01
    ldi     r17, 0x00
    sts     A_ADDR,   r16
    sts     A_ADDR+1, r17
    ldi     r16, 0x02
    ldi     r17, 0x00
    sts     B_ADDR,   r16
    sts     B_ADDR+1, r17

    ; keep a copy of the plaintext around so we can check the
    ; round trip once decrypt runs
    lds     r16, A_ADDR
    lds     r17, A_ADDR+1
    sts     A0_SAVE,   r16
    sts     A0_SAVE+1, r17
    lds     r16, B_ADDR
    lds     r17, B_ADDR+1
    sts     B0_SAVE,   r16
    sts     B0_SAVE+1, r17

    rcall   KEY_EXPANSION
    rcall   ENCRYPT

    ; stash the ciphertext somewhere separate so it doesn't just
    ; get overwritten the second DECRYPT runs - handy for actually
    ; looking at it in the simulator's memory view
    lds     r16, A_ADDR
    lds     r17, A_ADDR+1
    sts     CT_A_ADDR,   r16
    sts     CT_A_ADDR+1, r17
    lds     r16, B_ADDR
    lds     r17, B_ADDR+1
    sts     CT_B_ADDR,   r16
    sts     CT_B_ADDR+1, r17

    rcall   DECRYPT

    ; ---- self-check: did we get the original plaintext back? ----
    lds     r16, A_ADDR
    lds     r17, A0_SAVE
    cp      r16, r17
    brne    SELFTEST_FAIL
    lds     r16, A_ADDR+1
    lds     r17, A0_SAVE+1
    cp      r16, r17
    brne    SELFTEST_FAIL
    lds     r16, B_ADDR
    lds     r17, B0_SAVE
    cp      r16, r17
    brne    SELFTEST_FAIL
    lds     r16, B_ADDR+1
    lds     r17, B0_SAVE+1
    cp      r16, r17
    brne    SELFTEST_FAIL

    ldi     r16, 0x01
    sts     STATUS_ADDR, r16
    rjmp    DONE

SELFTEST_FAIL:
    ldi     r16, 0x00
    sts     STATUS_ADDR, r16

DONE:
    rjmp    DONE               ; halt here - check STATUS_ADDR in memory view

; ============================================================
; KEY_EXPANSION
; Expands K[0..11] into S[0..17]
; ============================================================
KEY_EXPANSION:

    ; ---- step 1: pack K[] into L[], 8-bit rotate as we go ----
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    ldi     r16, 0
    ldi     r17, 12
ZERO_L:
    st      Y+, r16
    dec     r17
    brne    ZERO_L

    ldi     r18, 11             ; i = 11 downto 0
STEP1_LOOP:
    mov     r19, r18
    lsr     r19                 ; word index = i/2

    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r24, r19
    lsl     r24                 ; byte offset = word_index*2 (Y here, not X, so this is safe)
    add     YL, r24
    adc     YH, r1
    ld      r20, Y+
    ld      r21, Y

    mov     r24, r20            ; swap bytes -> (L <<< 8)
    mov     r20, r21
    mov     r21, r24

    ldi     ZL, LOW(K_ADDR)
    ldi     ZH, HIGH(K_ADDR)
    add     ZL, r18
    adc     ZH, r1
    ld      r24, Z              ; K[i]

    clr     r25
    add     r20, r24
    adc     r21, r25

    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r24, r19
    lsl     r24
    add     YL, r24
    adc     YH, r1
    st      Y+, r20
    st      Y,  r21

    tst     r18
    breq    STEP1_DONE
    dec     r18
    rjmp    STEP1_LOOP
STEP1_DONE:

    ; ---- step 2: S[0] = P16, S[i] = S[i-1] + Q16 ----
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    ldi     r20, LOW(P16)
    ldi     r21, HIGH(P16)
    st      X+, r20
    st      X+, r21

    ldi     r18, 1
STEP2_LOOP:
    cpi     r18, T_SIZE
    brge    STEP2_DONE
    ldi     r24, LOW(Q16)
    ldi     r25, HIGH(Q16)
    add     r20, r24
    adc     r21, r25
    st      X+, r20
    st      X+, r21
    inc     r18
    rjmp    STEP2_LOOP
STEP2_DONE:

    ; ---- step 3: mix the key in, 54 passes ----
    clr     r20                 ; A = 0
    clr     r21
    clr     r22                 ; B = 0
    clr     r23
    clr     r18                 ; i = 0
    clr     r19                 ; j = 0
    ldi     r16, LOW(ITER)
    ldi     r17, HIGH(ITER)

STEP3_LOOP:
    cp      r16, r1
    cpc     r17, r1
    breq    STEP3_DONE

    ; A = S[i] = (S[i] + A + B) <<< 3
    ; NOTE: offset has to go somewhere that ISN'T r26 - r26 is XL, so
    ; loading the pointer right after wipes it out (this was the bug).
    ; Using r0 here instead of r24, and on purpose: ROL16_3 clobbers
    ; r24/r25/r26 internally, so whatever holds the offset needs to
    ; survive that call so it can be reused for the store-back below.
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    mov     r0, r18
    lsl     r0
    add     XL, r0
    adc     XH, r1
    ld      r24, X+
    ld      r25, X

    add     r24, r20
    adc     r25, r21
    add     r24, r22
    adc     r25, r23

    rcall   ROL16_3

    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r0              ; reuse the offset from above - ROL16_3 doesn't touch r0
    adc     XH, r1
    st      X+, r24
    st      X,  r25

    mov     r20, r24
    mov     r21, r25

    ; B = L[j] = (L[j] + A + B) <<< (A+B mod 16)  -- Y pointer, r26 is fine here
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r26, r19
    lsl     r26
    add     YL, r26
    adc     YH, r1
    ld      r24, Y+
    ld      r25, Y

    add     r24, r20
    adc     r25, r21
    add     r24, r22
    adc     r25, r23

    mov     r26, r20
    add     r26, r22
    andi    r26, 0x0F

    rcall   ROL16_VAR

    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r26, r19
    lsl     r26
    add     YL, r26
    adc     YH, r1
    st      Y+, r24
    st      Y,  r25

    mov     r22, r24
    mov     r23, r25

    inc     r18
    cpi     r18, T_SIZE
    brlt    NO_WRAP_I
    clr     r18
NO_WRAP_I:

    inc     r19
    cpi     r19, C_SIZE
    brlt    NO_WRAP_J
    clr     r19
NO_WRAP_J:

    subi    r16, 1
    sbci    r17, 0
    rjmp    STEP3_LOOP

STEP3_DONE:
    ret

; ============================================================
; ENCRYPT
; A/B in at A_ADDR/B_ADDR, result written back to the same spot
; ============================================================
ENCRYPT:
    lds     r20, A_ADDR
    lds     r21, A_ADDR+1
    lds     r22, B_ADDR
    lds     r23, B_ADDR+1

    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    ld      r24, X+
    ld      r25, X+
    add     r20, r24
    adc     r21, r25

    ld      r24, X+
    ld      r25, X+
    add     r22, r24
    adc     r23, r25

    ldi     r18, 1
ENC_LOOP:
    cpi     r18, ROUNDS+1
    brge    ENC_DONE

    mov     r24, r20
    mov     r25, r21
    eor     r24, r22
    eor     r25, r23

    mov     r26, r22
    andi    r26, 0x0F
    rcall   ROL16_VAR

    ; offset into r19, not r26 - same fix as above, S[2*i]
    mov     r19, r18
    lsl     r19
    lsl     r19
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r19
    adc     XH, r1
    ld      r16, X+
    ld      r17, X
    add     r24, r16
    adc     r25, r17

    mov     r20, r24
    mov     r21, r25

    mov     r24, r22
    mov     r25, r23
    eor     r24, r20
    eor     r25, r21

    mov     r26, r20
    andi    r26, 0x0F
    rcall   ROL16_VAR

    ; S[2*i+1]
    mov     r19, r18
    lsl     r19
    lsl     r19
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r19
    adc     XH, r1
    adiw    X, 2
    ld      r16, X+
    ld      r17, X
    add     r24, r16
    adc     r25, r17

    mov     r22, r24
    mov     r23, r25

    inc     r18
    rjmp    ENC_LOOP

ENC_DONE:
    sts     A_ADDR,   r20
    sts     A_ADDR+1, r21
    sts     B_ADDR,   r22
    sts     B_ADDR+1, r23
    ret

; ============================================================
; DECRYPT
; ciphertext in at A_ADDR/B_ADDR, plaintext written back to the same spot
; ============================================================
DECRYPT:
    lds     r20, A_ADDR
    lds     r21, A_ADDR+1
    lds     r22, B_ADDR
    lds     r23, B_ADDR+1

    ldi     r18, ROUNDS         ; i = 8 downto 1
DEC_LOOP:
    tst     r18
    breq    DEC_DONE

    ; Bi-1 = ((Bi - S[2*i+1]) >>> Ai) XOR Ai
    mov     r19, r18
    lsl     r19
    lsl     r19
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r19
    adc     XH, r1
    adiw    X, 2                ; -> S[2*i+1]
    ld      r16, X+
    ld      r17, X
    sub     r22, r16
    sbc     r23, r17

    mov     r26, r20
    andi    r26, 0x0F
    rcall   ROR16_VAR           ; r22:r23 >>> (A mod 16)

    eor     r22, r20
    eor     r23, r21

    ; Ai-1 = ((Ai - S[2*i]) >>> Bi-1) XOR Bi-1
    mov     r19, r18
    lsl     r19
    lsl     r19
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r19
    adc     XH, r1              ; -> S[2*i]
    ld      r16, X+
    ld      r17, X
    sub     r20, r16
    sbc     r21, r17

    mov     r24, r20
    mov     r25, r21
    mov     r26, r22
    andi    r26, 0x0F
    rcall   ROR16_VAR           ; r24:r25 >>> (new B mod 16)

    eor     r24, r22
    eor     r25, r23
    mov     r20, r24
    mov     r21, r25

    dec     r18
    rjmp    DEC_LOOP

DEC_DONE:
    ldi     XL, LOW(S_ADDR+2)
    ldi     XH, HIGH(S_ADDR+2)
    ld      r24, X+
    ld      r25, X
    sub     r22, r24
    sbc     r23, r25            ; B0 = B - S[1]

    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    ld      r24, X+
    ld      r25, X
    sub     r20, r24
    sbc     r21, r25            ; A0 = A - S[0]

    sts     A_ADDR,   r20
    sts     A_ADDR+1, r21
    sts     B_ADDR,   r22
    sts     B_ADDR+1, r23
    ret

; ============================================================
; rotate helpers - all operate on r24:r25, count in r26
; ============================================================
ROL16_3:
    ldi     r26, 3
ROL16_3_LOOP:
    lsl     r24
    rol     r25
    brcc    ROL16_3_NC
    ori     r24, 0x01
ROL16_3_NC:
    dec     r26
    brne    ROL16_3_LOOP
    ret

ROL16_VAR:
    tst     r26
    breq    ROL16V_DONE
ROL16V_LOOP:
    lsl     r24
    rol     r25
    brcc    ROL16V_NC
    ori     r24, 0x01
ROL16V_NC:
    dec     r26
    brne    ROL16V_LOOP
ROL16V_DONE:
    ret

ROR16_VAR:
    tst     r26
    breq    ROR16V_DONE
ROR16V_LOOP:
    lsr     r25
    ror     r24
    brcc    ROR16V_NC
    ori     r25, 0x80
ROR16V_NC:
    dec     r26
    brne    ROR16V_LOOP
ROR16V_DONE:
    ret
