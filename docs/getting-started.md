# Getting Started

← [Back to README](../README.md)

---

## Install the library

```sh
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/Qt -DCMAKE_INSTALL_PREFIX=/path/to/install
cmake --build build
cmake --install build
```

### Optional CMake flags

```sh
cmake -B build \
  -DQTAES_ENABLE_AESNI=ON \              # Hardware AES-NI acceleration (all modes)
  -DQTAES_ENABLE_TESTS=ON \             # Build unit tests
  -DQTAES_ENABLE_WERROR=ON \            # Treat warnings as errors
  -DQTAES_ENABLE_SANITIZERS=ON \        # AddressSanitizer + UBSan (GCC/Clang only)
  -DQTAES_ENABLE_FUZZING=ON \           # libFuzzer fuzz target (Clang only)
  -DQTAES_ENABLE_OPENSSL_CROSS_CHECK=ON # OpenSSL interop cross-check tests
```

---

## Use in your project

In your `CMakeLists.txt`:

```cmake
find_package(QtAES REQUIRED)
target_link_libraries(your_target PRIVATE QtAES::QtAES)
```

Then include as you would any Qt class header:

```cpp
#include <QAESEncryption>
```

Pass the install prefix to CMake so `find_package` can locate the library:

```sh
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/install
```

---

## Embed as a subdirectory

Alternatively, copy the source tree into your project and use `add_subdirectory`:

```cmake
add_subdirectory(Qt-AES)
target_link_libraries(your_target PRIVATE QtAES::QtAES)
```
