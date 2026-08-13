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
;   - Iterations     = 54  (3 * max(18,6) = 3*18)
;
; Register Usage Convention:
;   R0:R1   - Temporary / MUL result
;   R16:R17 - General purpose temp (16-bit pair, low:high)
;   R18:R19 - General purpose temp
;   R20:R21 - A (16-bit, low:high)
;   R22:R23 - B (16-bit, low:high)
;   R24:R25 - Shift count / misc temp
;   R26:R27 - X pointer (used for S[] array)
;   R28:R29 - Y pointer (used for L[] array)
;   R30:R31 - Z pointer (used for K[] key array)
;
; Memory Map (SRAM):
;   0x0100 - 0x010B  : K[0..11]  Secret key (12 bytes)
;   0x0110 - 0x011B  : L[0..5]   Key words   (6 * 2 = 12 bytes)
;   0x0120 - 0x0143  : S[0..17]  Expanded key table (18 * 2 = 36 bytes)
;   0x0150 - 0x0151  : plaintext A0 (16-bit)
;   0x0152 - 0x0153  : plaintext B0 (16-bit)
;   0x0154 - 0x0155  : ciphertext Ar (16-bit)
;   0x0156 - 0x0157  : ciphertext Br (16-bit)
; ============================================================

.include "m32def.inc"       ; or m328Pdef.inc for ATmega328P

; ---- Constants ----
.equ P16,     0xB7E1
.equ Q16,     0x9E37
.equ ROUNDS,  8
.equ T_SIZE,  18            ; 2*(r+1) = 18
.equ C_SIZE,  6             ; key words
.equ B_SIZE,  12            ; key bytes
.equ ITER,    54            ; 3*18

; ---- SRAM Addresses ----
.equ K_ADDR,  0x0100        ; Secret key bytes K[0..11]
.equ L_ADDR,  0x0110        ; Key words L[0..5]  (2 bytes each)
.equ S_ADDR,  0x0120        ; Expanded key S[0..17] (2 bytes each)
.equ A_ADDR,  0x0150        ; 16-bit A (plaintext input / ciphertext output)
.equ B_ADDR,  0x0152        ; 16-bit B

; ============================================================
.cseg
.org 0x0000
    rjmp    MAIN

; ============================================================
; MAIN
; ============================================================
MAIN:
    ; --- Stack pointer init ---
    ldi     r16, HIGH(RAMEND)
    out     SPH, r16
    ldi     r16, LOW(RAMEND)
    out     SPL, r16

    ; --- Load a test key into K[0..11] ---
    ; Key = 00 01 02 03 04 05 06 07 08 09 0A 0B
    ldi     ZL, LOW(K_ADDR)
    ldi     ZH, HIGH(K_ADDR)
    ldi     r16, 0x00
    ldi     r17, 0x0C       ; 12 bytes
LOAD_KEY:
    st      Z+, r16
    inc     r16
    dec     r17
    brne    LOAD_KEY

    ; --- Load plaintext: A0=0x0001, B0=0x0002 ---
    ldi     r16, 0x01
    ldi     r17, 0x00
    sts     A_ADDR,   r16
    sts     A_ADDR+1, r17
    ldi     r16, 0x02
    ldi     r17, 0x00
    sts     B_ADDR,   r16
    sts     B_ADDR+1, r17

    ; ---- Run Key Expansion ----
    rcall   KEY_EXPANSION

    ; ---- Run Encryption ----
    rcall   ENCRYPT

    ; ---- (Optional) Run Decryption ----
    ; rcall DECRYPT

DONE:
    rjmp    DONE            ; Halt / infinite loop

; ============================================================
; KEY_EXPANSION
; Expands K[0..11] into S[0..17]
; ============================================================
KEY_EXPANSION:

    ; ------ STEP 1: Copy K[] into L[] with 8-bit left rotate ------
    ; L[i/u] = (L[i/u] <<< 8) + K[i]   for i = 11 downto 0
    ; Since u=2 (bytes/word), L[0] gets K[1]:K[0], L[1] gets K[3]:K[2], etc.
    ; Initialize L[0..5] = 0
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    ldi     r16, 0
    ldi     r17, 12         ; 12 bytes to zero
ZERO_L:
    st      Y+, r16
    dec     r17
    brne    ZERO_L

    ; Loop i = 11 downto 0
    ldi     r18, 11         ; i = 11
STEP1_LOOP:
    ; Compute index into L: r19 = i/2 (word index)
    mov     r19, r18
    lsr     r19             ; r19 = i/2

    ; Load L[r19] (16-bit) into r20:r21
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r24, r19
    lsl     r24             ; byte offset = word_index * 2
    add     YL, r24
    adc     YH, r1          ; r1=0 after lsl with no carry expected here
    ld      r20, Y+
    ld      r21, Y

    ; Rotate L[r19] left by 8 bits: swap bytes
    ; (L <<< 8) means high byte becomes low, low becomes high
    mov     r24, r20
    mov     r20, r21
    mov     r21, r24

    ; Load K[i]
    ldi     ZL, LOW(K_ADDR)
    ldi     ZH, HIGH(K_ADDR)
    add     ZL, r18
    adc     ZH, r1
    ld      r24, Z          ; r24 = K[i]

    ; L[r19] = L[r19] + K[i]   (16-bit add of 8-bit value)
    clr     r25
    add     r20, r24
    adc     r21, r25

    ; Store back L[r19]
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r24, r19
    lsl     r24
    add     YL, r24
    adc     YH, r1
    st      Y+, r20
    st      Y,  r21

    ; Decrement i, loop while i >= 0
    tst     r18
    breq    STEP1_DONE
    dec     r18
    rjmp    STEP1_LOOP
STEP1_DONE:

    ; ------ STEP 2: Initialize S[] ------
    ; S[0] = P16
    ; S[i] = S[i-1] + Q16  for i=1..17
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    ldi     r20, LOW(P16)
    ldi     r21, HIGH(P16)
    st      X+, r20
    st      X+, r21         ; S[0] = P16

    ldi     r18, 1          ; i = 1
STEP2_LOOP:
    cpi     r18, T_SIZE     ; 18
    brge    STEP2_DONE
    ; S[i] = S[i-1] + Q16
    ldi     r24, LOW(Q16)
    ldi     r25, HIGH(Q16)
    add     r20, r24
    adc     r21, r25
    st      X+, r20
    st      X+, r21
    inc     r18
    rjmp    STEP2_LOOP
STEP2_DONE:

    ; ------ STEP 3: Mix secret key into S[] ------
    ; i=j=0, A=B=0
    ; do 54 times:
    ;   A = S[i] = (S[i] + A + B) <<< 3
    ;   B = L[j] = (L[j] + A + B) <<< (A+B)
    ;   i = (i+1) mod 18
    ;   j = (j+1) mod 6
    clr     r20             ; A_low  = 0
    clr     r21             ; A_high = 0
    clr     r22             ; B_low  = 0
    clr     r23             ; B_high = 0
    clr     r18             ; i = 0
    clr     r19             ; j = 0
    ldi     r16, LOW(ITER)  ; iteration counter = 54
    ldi     r17, HIGH(ITER)

STEP3_LOOP:
    ; Check counter
    cp      r16, r1
    cpc     r17, r1
    breq    STEP3_DONE

    ; ---- A = S[i] = (S[i] + A + B) <<< 3 ----
    ; Load S[i] into r24:r25
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    mov     r26, r18
    lsl     r26             ; byte offset = i*2
    add     XL, r26
    adc     XH, r1
    ld      r24, X+
    ld      r25, X

    ; r24:r25 = S[i] + A + B
    add     r24, r20
    adc     r25, r21
    add     r24, r22
    adc     r25, r23

    ; Rotate left by 3: call ROL16_3
    rcall   ROL16_3         ; result in r24:r25

    ; S[i] = r24:r25
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    mov     r26, r18
    lsl     r26
    add     XL, r26
    adc     XH, r1
    st      X+, r24
    st      X,  r25

    ; A = r24:r25
    mov     r20, r24
    mov     r21, r25

    ; ---- B = L[j] = (L[j] + A + B) <<< (A+B) ----
    ; Load L[j] into r24:r25
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r26, r19
    lsl     r26
    add     YL, r26
    adc     YH, r1
    ld      r24, Y+
    ld      r25, Y

    ; r24:r25 = L[j] + A + B
    add     r24, r20
    adc     r25, r21
    add     r24, r22
    adc     r25, r23

    ; Shift amount = (A + B) mod 16
    mov     r26, r20
    add     r26, r22        ; low byte of (A+B), mod 16 = lower 4 bits
    andi    r26, 0x0F

    ; Rotate left by r26 bits
    rcall   ROL16_VAR       ; r24:r25 <<< r26 => result in r24:r25

    ; L[j] = r24:r25
    ldi     YL, LOW(L_ADDR)
    ldi     YH, HIGH(L_ADDR)
    mov     r26, r19
    lsl     r26
    add     YL, r26
    adc     YH, r1
    st      Y+, r24
    st      Y,  r25

    ; B = r24:r25
    mov     r22, r24
    mov     r23, r25

    ; i = (i+1) mod 18
    inc     r18
    cpi     r18, T_SIZE
    brlt    NO_WRAP_I
    clr     r18
NO_WRAP_I:

    ; j = (j+1) mod 6
    inc     r19
    cpi     r19, C_SIZE
    brlt    NO_WRAP_J
    clr     r19
NO_WRAP_J:

    ; Decrement iteration counter (16-bit)
    subi    r16, 1
    sbci    r17, 0
    rjmp    STEP3_LOOP

STEP3_DONE:
    ret

; ============================================================
; ENCRYPT
; A0, B0 are at A_ADDR, B_ADDR (16-bit little-endian)
; Result stored back to A_ADDR, B_ADDR
; ============================================================
ENCRYPT:
    ; Load A0, B0
    lds     r20, A_ADDR
    lds     r21, A_ADDR+1
    lds     r22, B_ADDR
    lds     r23, B_ADDR+1

    ; A0 = A0 + S[0]
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    ld      r24, X+
    ld      r25, X+
    add     r20, r24
    adc     r21, r25

    ; B0 = B0 + S[1]
    ld      r24, X+
    ld      r25, X+
    add     r22, r24
    adc     r23, r25

    ; Loop i=1 to 8
    ldi     r18, 1          ; round counter i
ENC_LOOP:
    cpi     r18, ROUNDS+1   ; i > 8?
    brge    ENC_DONE

    ; Ai = ((A XOR B) <<< B) + S[2*i]
    mov     r24, r20
    mov     r25, r21
    eor     r24, r22        ; r24:r25 = A XOR B
    eor     r25, r23

    ; Rotate left by (B mod 16)
    mov     r26, r22
    andi    r26, 0x0F
    rcall   ROL16_VAR       ; r24:r25 <<< (B mod 16)

    ; + S[2*i]  -- offset = 2*i*2 = 4*i bytes from S_ADDR (but S_ADDR already holds 16-bit words)
    ; S word index = 2*i, byte offset = 4*i
    mov     r26, r18
    lsl     r26
    lsl     r26             ; r26 = 4*i  (byte offset for S[2*i])
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r26
    adc     XH, r1
    ld      r26, X+
    ld      r27, X
    add     r24, r26
    adc     r25, r27

    ; Save new A
    mov     r20, r24
    mov     r21, r25

    ; Bi = ((B XOR A) <<< A) + S[2*i+1]
    mov     r24, r22
    mov     r25, r23
    eor     r24, r20        ; r24:r25 = B XOR new_A
    eor     r25, r21

    ; Rotate left by (A mod 16)
    mov     r26, r20
    andi    r26, 0x0F
    rcall   ROL16_VAR

    ; + S[2*i+1], byte offset = 4*i + 2
    mov     r26, r18
    lsl     r26
    lsl     r26
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r26
    adc     XH, r1
    adiw    X, 2            ; point to S[2*i+1]
    ld      r26, X+
    ld      r27, X
    add     r24, r26
    adc     r25, r27

    mov     r22, r24
    mov     r23, r25

    inc     r18
    rjmp    ENC_LOOP

ENC_DONE:
    ; Store results
    sts     A_ADDR,   r20
    sts     A_ADDR+1, r21
    sts     B_ADDR,   r22
    sts     B_ADDR+1, r23
    ret

; ============================================================
; DECRYPT
; Encrypted A, B at A_ADDR, B_ADDR
; Result stored back
; ============================================================
DECRYPT:
    lds     r20, A_ADDR
    lds     r21, A_ADDR+1
    lds     r22, B_ADDR
    lds     r23, B_ADDR+1

    ldi     r18, ROUNDS     ; i = 8 downto 1
DEC_LOOP:
    tst     r18
    breq    DEC_DONE

    ; Bi-1 = ((Bi - S[2*i+1]) >>> Ai) XOR Ai
    mov     r26, r18
    lsl     r26
    lsl     r26             ; 4*i
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r26
    adc     XH, r1
    adiw    X, 2            ; S[2*i+1]
    ld      r24, X+
    ld      r25, X
    sub     r22, r24
    sbc     r23, r25        ; B - S[2*i+1]

    ; Rotate right by (Ai mod 16)
    mov     r26, r20
    andi    r26, 0x0F
    rcall   ROR16_VAR       ; r22:r23 >>> A

    eor     r22, r20        ; XOR Ai  => Bi-1
    eor     r23, r21

    ; Ai-1 = ((Ai - S[2*i]) >>> Bi-1) XOR Bi-1
    mov     r26, r18
    lsl     r26
    lsl     r26
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    add     XL, r26
    adc     XH, r1          ; S[2*i]
    ld      r24, X+
    ld      r25, X
    sub     r20, r24
    sbc     r21, r25        ; A - S[2*i]

    ; Rotate right by (Bi-1 mod 16)
    mov     r24, r22
    mov     r25, r23
    mov     r26, r22
    andi    r26, 0x0F
    ; need to rotate r20:r21 right by r26
    ; swap vars: put A in r24:r25 for ROR routine
    mov     r24, r20
    mov     r25, r21
    rcall   ROR16_VAR

    eor     r24, r22        ; XOR Bi-1 => Ai-1
    eor     r25, r23
    mov     r20, r24
    mov     r21, r25

    dec     r18
    rjmp    DEC_LOOP

DEC_DONE:
    ; B0 = B0 - S[1]
    ldi     XL, LOW(S_ADDR+2)
    ldi     XH, HIGH(S_ADDR+2)
    ld      r24, X+
    ld      r25, X
    sub     r22, r24
    sbc     r23, r25

    ; A0 = A0 - S[0]
    ldi     XL, LOW(S_ADDR)
    ldi     XH, HIGH(S_ADDR)
    ld      r24, X+
    ld      r25, X
    sub     r20, r24
    sbc     r21, r25

    sts     A_ADDR,   r20
    sts     A_ADDR+1, r21
    sts     B_ADDR,   r22
    sts     B_ADDR+1, r23
    ret

; ============================================================
; ROL16_3  - Rotate 16-bit value in r24:r25 left by 3 bits
; Result in r24:r25
; ============================================================
ROL16_3:
    ldi     r26, 3
ROL16_3_LOOP:
    lsl     r24
    rol     r25
    brcc    ROL16_3_NC
    ori     r24, 0x01       ; bring carry into bit0
ROL16_3_NC:
    dec     r26
    brne    ROL16_3_LOOP
    ret

; ============================================================
; ROL16_VAR - Rotate 16-bit value in r24:r25 left by r26 bits (0..15)
; Result in r24:r25
; ============================================================
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

; ============================================================
; ROR16_VAR - Rotate 16-bit value in r24:r25 right by r26 bits (0..15)
; Result in r24:r25
; ============================================================
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

