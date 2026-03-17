# Testing & Fuzzing

← [Back to README](../README.md)

---

## Unit Tests

Test vectors are taken from [NIST SP 800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
for ECB, CBC, CFB, OFB, and CTR modes across all key sizes.
`generateKey()` is validated against five PBKDF2-HMAC-SHA256 vectors cross-checked with
Python's `hashlib.pbkdf2_hmac`.

```sh
cmake -B build -DQTAES_ENABLE_TESTS=ON -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build
ctest --test-dir build -V
```

### OpenSSL interop cross-check

A separate test binary (`AESCrossCheck`) verifies byte-for-byte compatibility between Qt-AES
and OpenSSL's EVP API in both directions (Qt→OpenSSL and OpenSSL→Qt) for all 5 modes × 3 key
sizes, using NIST SP 800-38A plaintext/keys/IVs, plus corner cases for empty input and
sub-block partial plaintext.

Requires `libssl-dev` (or equivalent) on the build host.

```sh
cmake -B build \
  -DQTAES_ENABLE_TESTS=ON \
  -DQTAES_ENABLE_OPENSSL_CROSS_CHECK=ON \
  -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build
ctest --test-dir build -V
```

---

## Fuzzing

A [libFuzzer](https://llvm.org/docs/LibFuzzer.html) fuzz target lives in `fuzz/fuzz_encrypt.cpp`.
It exercises all five cipher modes, all three key sizes, and all three padding schemes against
randomly mutated inputs, and checks two properties on every input:

1. **Crash freedom** — neither `encode()` nor `decode()` ever crashes or triggers memory errors
   (AddressSanitizer is always active with `-fsanitize=fuzzer`).
2. **Round-trip correctness** — for PKCS7 padding, `removePadding(decode(encode(pt))) == pt`;
   for CTR mode, `decode(encode(pt)) == pt` directly.

### Building and running

```sh
cmake -B build-fuzz \
  -DQTAES_ENABLE_FUZZING=ON \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_PREFIX_PATH=/path/to/Qt

cmake --build build-fuzz --target fuzz_encrypt

# Run for 60 seconds, seeding from the provided corpus:
./build-fuzz/fuzz_encrypt fuzz/corpus/ -max_total_time=60
```

The `fuzz/corpus/` directory contains seed inputs that cover all mode/level/padding
combinations, giving the fuzzer a head start.
