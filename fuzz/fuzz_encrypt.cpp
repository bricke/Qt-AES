/*
 * Fuzz target for QAESEncryption using libFuzzer.
 *
 * Build with:
 *   cmake -B build-fuzz -DQTAES_ENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++ \
 *         -DCMAKE_PREFIX_PATH=/path/to/Qt
 *   cmake --build build-fuzz --target fuzz_encrypt
 *
 * Run:
 *   ./build-fuzz/fuzz_encrypt fuzz/corpus/ -max_total_time=60
 *
 * The fuzzer checks two properties on every input:
 *   1. Neither encode() nor decode() ever crashes or triggers memory errors
 *      (AddressSanitizer and UBSan are always active with -fsanitize=fuzzer).
 *   2. Round-trip: for PKCS7 padding, removePadding(decode(encode(pt))) == pt.
 *      For CTR (stream cipher, no padding), decode(encode(pt)) == pt directly.
 *
 * Input layout (minimum 51 bytes):
 *   [0]      mode    — value % 5  → ECB / CBC / CFB / OFB / CTR
 *   [1]      level   — value % 3  → AES-128 / AES-192 / AES-256
 *   [2]      padding — value % 3  → ZERO / PKCS7 / ISO
 *   [3..34]  32-byte key area (AES-128 uses first 16, AES-192 first 24, AES-256 all 32)
 *   [35..50] 16-byte IV
 *   [51..]   plaintext (any length, including zero)
 */

#include "qaesencryption.h"

#include <QByteArray>
#include <QCoreApplication>
#include <cassert>
#include <cstdint>
#include <cstdlib>

// libFuzzer calls this once before the first test input.
// Initialise a QCoreApplication so Qt's internal plumbing is ready.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    static QCoreApplication app(*argc, *argv);
    (void)app;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Fixed header: 3 selector bytes + 32-byte key area + 16-byte IV.
    static const size_t KEY_AREA = 32;
    static const size_t IV_SIZE  = 16;
    static const size_t HEADER   = 3 + KEY_AREA + IV_SIZE; // 51 bytes

    if (size < HEADER)
        return 0;

    // Parse selectors.
    const auto mode    = static_cast<QAESEncryption::Mode>   (data[0] % 5);
    const auto level   = static_cast<QAESEncryption::Aes>    (data[1] % 3);
    const auto padding = static_cast<QAESEncryption::Padding>(data[2] % 3);

    // Key: AES-128 → 16 bytes, AES-192 → 24 bytes, AES-256 → 32 bytes.
    static const int keySizes[] = {16, 24, 32};
    const int keySize = keySizes[data[1] % 3];

    const QByteArray key(reinterpret_cast<const char *>(data + 3),        keySize);
    const QByteArray iv (reinterpret_cast<const char *>(data + 3 + KEY_AREA), static_cast<int>(IV_SIZE));
    const QByteArray pt (reinterpret_cast<const char *>(data + HEADER),   static_cast<int>(size - HEADER));

    QAESEncryption enc(level, mode, padding);

    // --- Property 1: encode() must never crash ---
    bool encOk = false;
    const QByteArray ct = enc.encode(pt, key, iv, &encOk);

    if (!encOk)
        return 0; // invalid input (wrong key/IV size) — not a bug

    // --- Property 1 continued: decode() on valid ciphertext must never crash ---
    bool decOk = false;
    const QByteArray decrypted = enc.decode(ct, key, iv, &decOk);

    if (!decOk) {
        // encode() succeeded but decode() rejected the same ciphertext — bug.
        abort();
    }

    // --- Property 2: round-trip correctness ---
    if (mode == QAESEncryption::CTR) {
        // CTR is a stream cipher: no padding, so decode(encode(pt)) must equal pt exactly.
        if (decrypted != pt)
            abort();
    } else if (padding == QAESEncryption::PKCS7) {
        // PKCS7 always adds at least one byte and validates every padding byte on removal,
        // so the round-trip is well-defined for any plaintext.
        bool padOk = false;
        const QByteArray recovered = enc.removePadding(decrypted, &padOk);
        if (!padOk || recovered != pt)
            abort();
    }
    // ZERO and ISO padding have corner cases (trailing zeros / trailing 0x80) that make
    // the round-trip ambiguous for certain plaintexts; only crash-freedom is checked.

    return 0;
}
