#ifndef AES_CT_SBOX_H
#define AES_CT_SBOX_H

// Constant-time AES S-box — Boyar-Peralta algebraic circuit.
//
// Computes the same values as the standard 256-byte lookup table but uses
// only bitwise AND/XOR on individual bits, eliminating data-dependent
// memory accesses that leak information through CPU cache timing.
//
// Reference: Boyar & Peralta, "A depth-16 circuit for the AES S-box",
//            IACR ePrint 2011/332.
//
// The inverse S-box reuses the forward circuit via the identity
//   S^{-1}(y) = invAffine(S(invAffine(y)))
// where invAffine is the inverse of the AES affine transform (FIPS 197 §5.1.1).

#include <QtGlobal>

namespace AesCt {

inline quint8 rotl8(quint8 x, unsigned n)
{
    return static_cast<quint8>((x << n) | (x >> (8 - n)));
}

// Inverse of the AES affine transform: A^{-1} * (x ^ 0x63).
// FIPS 197 §5.3.2: b'_i = b_{(i+2)%8} ^ b_{(i+5)%8} ^ b_{(i+7)%8} ^ d_i
// which is: rotl(x,1) ^ rotl(x,3) ^ rotl(x,6) ^ 0x05.
inline quint8 invAffine(quint8 x)
{
    return rotl8(x, 1) ^ rotl8(x, 3) ^ rotl8(x, 6) ^ 0x05;
}

// Forward AES S-box computed via the Boyar-Peralta circuit.
// Input/output: one byte.  No table lookups — all operations are
// register-only AND/XOR on individual bits.
inline quint8 sbox(quint8 input)
{
    // Extract individual bits (U0 = MSB = bit 7, U7 = LSB = bit 0)
    const quint8 U0 = (input >> 7) & 1;
    const quint8 U1 = (input >> 6) & 1;
    const quint8 U2 = (input >> 5) & 1;
    const quint8 U3 = (input >> 4) & 1;
    const quint8 U4 = (input >> 3) & 1;
    const quint8 U5 = (input >> 2) & 1;
    const quint8 U6 = (input >> 1) & 1;
    const quint8 U7 = input & 1;

    // --- Top linear transform (27 XOR gates) ---
    const quint8 T1  = U0 ^ U3;
    const quint8 T2  = U0 ^ U5;
    const quint8 T3  = U0 ^ U6;
    const quint8 T4  = U3 ^ U5;
    const quint8 T5  = U4 ^ U6;
    const quint8 T6  = T1 ^ T5;
    const quint8 T7  = U1 ^ U2;
    const quint8 T8  = U7 ^ T6;
    const quint8 T9  = U7 ^ T7;
    const quint8 T10 = T6 ^ T7;
    const quint8 T11 = U1 ^ U5;
    const quint8 T12 = U2 ^ U5;
    const quint8 T13 = T3 ^ T4;
    const quint8 T14 = T6 ^ T11;
    const quint8 T15 = T5 ^ T11;
    const quint8 T16 = T5 ^ T12;
    const quint8 T17 = T9 ^ T16;
    const quint8 T18 = U3 ^ U7;
    const quint8 T19 = T7 ^ T18;
    const quint8 T20 = T1 ^ T19;
    const quint8 T21 = U6 ^ U7;
    const quint8 T22 = T7 ^ T21;
    const quint8 T23 = T2 ^ T22;
    const quint8 T24 = T2 ^ T10;
    const quint8 T25 = T20 ^ T17;
    const quint8 T26 = T3 ^ T16;
    const quint8 T27 = T1 ^ T12;

    // --- Non-linear middle section (34 AND + 29 XOR gates) ---
    const quint8 M1  = T13 & T6;
    const quint8 M2  = T23 & T8;
    const quint8 M3  = T14 ^ M1;
    const quint8 M4  = T19 & U7;
    const quint8 M5  = M4 ^ M1;
    const quint8 M6  = T3 & T16;
    const quint8 M7  = T22 & T9;
    const quint8 M8  = T26 ^ M6;
    const quint8 M9  = T20 & T17;
    const quint8 M10 = M9 ^ M6;
    const quint8 M11 = T1 & T15;
    const quint8 M12 = T4 & T27;
    const quint8 M13 = M12 ^ M11;
    const quint8 M14 = T2 & T10;
    const quint8 M15 = M14 ^ M11;
    const quint8 M16 = M3 ^ M2;
    const quint8 M17 = M5 ^ T24;
    const quint8 M18 = M8 ^ M7;
    const quint8 M19 = M10 ^ M15;
    const quint8 M20 = M16 ^ M13;
    const quint8 M21 = M17 ^ M15;
    const quint8 M22 = M18 ^ M13;
    const quint8 M23 = M19 ^ T25;
    const quint8 M24 = M22 ^ M23;
    const quint8 M25 = M22 & M20;
    const quint8 M26 = M21 ^ M25;
    const quint8 M27 = M20 ^ M21;
    const quint8 M28 = M23 ^ M25;
    const quint8 M29 = M28 & M27;
    const quint8 M30 = M26 & M24;
    const quint8 M31 = M20 & M23;
    const quint8 M32 = M27 & M31;
    const quint8 M33 = M27 ^ M25;
    const quint8 M34 = M21 & M22;
    const quint8 M35 = M24 & M34;
    const quint8 M36 = M24 ^ M25;
    const quint8 M37 = M21 ^ M29;
    const quint8 M38 = M32 ^ M33;
    const quint8 M39 = M23 ^ M30;
    const quint8 M40 = M35 ^ M36;
    const quint8 M41 = M38 ^ M40;
    const quint8 M42 = M37 ^ M39;
    const quint8 M43 = M37 ^ M38;
    const quint8 M44 = M39 ^ M40;
    const quint8 M45 = M42 ^ M41;

    // --- Shared-factor multiplication (18 AND gates) ---
    const quint8 M46 = M44 & T6;
    const quint8 M47 = M40 & T8;
    const quint8 M48 = M39 & U7;
    const quint8 M49 = M43 & T16;
    const quint8 M50 = M38 & T9;
    const quint8 M51 = M37 & T17;
    const quint8 M52 = M42 & T15;
    const quint8 M53 = M45 & T27;
    const quint8 M54 = M41 & T10;
    const quint8 M55 = M44 & T13;
    const quint8 M56 = M40 & T23;
    const quint8 M57 = M39 & T19;
    const quint8 M58 = M43 & T3;
    const quint8 M59 = M38 & T22;
    const quint8 M60 = M37 & T20;
    const quint8 M61 = M42 & T1;
    const quint8 M62 = M45 & T4;
    const quint8 M63 = M41 & T2;

    // --- Bottom linear transform (30 XOR gates) ---
    const quint8 L0  = M61 ^ M62;
    const quint8 L1  = M50 ^ M56;
    const quint8 L2  = M46 ^ M48;
    const quint8 L3  = M47 ^ M55;
    const quint8 L4  = M54 ^ M58;
    const quint8 L5  = M49 ^ M61;
    const quint8 L6  = M62 ^ L5;
    const quint8 L7  = M46 ^ L3;
    const quint8 L8  = M51 ^ M59;
    const quint8 L9  = M52 ^ M53;
    const quint8 L10 = M53 ^ L4;
    const quint8 L11 = M60 ^ L2;
    const quint8 L12 = M48 ^ M51;
    const quint8 L13 = M50 ^ L0;
    const quint8 L14 = M52 ^ M61;
    const quint8 L15 = M55 ^ L1;
    const quint8 L16 = M56 ^ L0;
    const quint8 L17 = M57 ^ L1;
    const quint8 L18 = M58 ^ L8;
    const quint8 L19 = M63 ^ L4;
    const quint8 L20 = L0 ^ L1;
    const quint8 L21 = L1 ^ L7;
    const quint8 L22 = L3 ^ L12;
    const quint8 L23 = L18 ^ L2;
    const quint8 L24 = L15 ^ L9;
    const quint8 L25 = L6 ^ L10;
    const quint8 L26 = L7 ^ L9;
    const quint8 L27 = L8 ^ L10;
    const quint8 L28 = L11 ^ L14;
    const quint8 L29 = L11 ^ L17;

    // Output bits (NOT on S1, S2, S6, S7 implements the affine constant 0x63)
    const quint8 S0 = (L6  ^ L24) & 1;
    const quint8 S1 = (1 ^ (L16 ^ L26)) & 1;
    const quint8 S2 = (1 ^ (L19 ^ L28)) & 1;
    const quint8 S3 = (L6  ^ L21) & 1;
    const quint8 S4 = (L20 ^ L22) & 1;
    const quint8 S5 = (L25 ^ L29) & 1;
    const quint8 S6 = (1 ^ (L13 ^ L27)) & 1;
    const quint8 S7 = (1 ^ (L6  ^ L23)) & 1;

    return static_cast<quint8>(
        (S0 << 7) | (S1 << 6) | (S2 << 5) | (S3 << 4) |
        (S4 << 3) | (S5 << 2) | (S6 << 1) | S7);
}

// Inverse AES S-box, computed as: invAffine(sbox(invAffine(y))).
// This reuses the forward circuit rather than maintaining a second circuit.
inline quint8 invSbox(quint8 input)
{
    return invAffine(sbox(invAffine(input)));
}

} // namespace AesCt

#endif // AES_CT_SBOX_H
