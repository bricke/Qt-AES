# API Reference

← [Back to README](../README.md)

---

## Constructor

```cpp
QAESEncryption(Aes level, Mode mode, Padding padding = ISO);
```

### Supported values

| Enum | Values |
|------|--------|
| `QAESEncryption::Aes` | `AES_128`, `AES_192`, `AES_256` |
| `QAESEncryption::Mode` | `ECB`, `CBC`, `CFB`, `OFB`, `CTR` |
| `QAESEncryption::Padding` | `ISO` (default), `PKCS7`, `ZERO`, `NONE` |

> **`Padding::NONE`** disables padding entirely. Valid for stream cipher modes (CFB, OFB, CTR),
> which operate byte-by-byte and do not require block alignment. Using `NONE` with ECB or CBC
> on non-block-aligned input returns an empty `QByteArray` and sets `ok = false`.

---

## Instance methods

| Method | Description |
|--------|-------------|
| `encode(rawText, key, iv, ok)` | Encrypt `rawText` with `key`. `iv` required for CBC/CFB/OFB/CTR. Optional `bool *ok` set to `false` on invalid key/IV. |
| `decode(rawText, key, iv, ok)` | Decrypt `rawText` with `key`. `iv` required for CBC/CFB/OFB/CTR. Optional `bool *ok` set to `false` on invalid input. |
| `removePadding(rawText, ok)` | Strip padding from a decrypted result. Optional `bool *ok` set to `false` if PKCS7 padding is invalid. |

All `ok` parameters default to `nullptr` — existing code requires no changes.

---

## Static methods

| Method | Description |
|--------|-------------|
| `QAESEncryption::Crypt(..., ok)` | Static encrypt — no instance needed. Optional `bool *ok`. |
| `QAESEncryption::Decrypt(..., ok)` | Static decrypt — no instance needed. Optional `bool *ok`. |
| `QAESEncryption::RemovePadding(..., ok)` | Static padding removal. Optional `bool *ok`. |
| `QAESEncryption::ExpandKey(...)` | Static key expansion — advanced use; `encode`/`decode` handle this internally. |
| `QAESEncryption::generateKey(password, salt, level, algo, iterations)` | Derive an AES-ready key via PBKDF2-HMAC (SHA-256 by default, 10 000 iterations). |

---

## Thread safety

Instances are thread-safe. All mutable state during `encode()` / `decode()` is kept on the
call stack — no member variables are written after construction. Multiple threads may call
`encode()` or `decode()` on the same instance concurrently without a mutex.

The static methods (`Crypt`, `Decrypt`, `ExpandKey`, `RemovePadding`, `generateKey`) are also
safe to call concurrently.
