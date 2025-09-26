# OpenSSL EVP WASM Bindings

This project provides Webassembly bindings for OpenSSL's EVP interface powered by Emscripten, giving javascript direct access to libcrypto's cryptographic functions.

These binding are intended to be used by web apps without easy access to cryptographic libraries outside of webcrypto. In particular, they allow web apps to generate the ML-KEM PQC keys made available starting in OpenSSL 3.5+, which are not yet available in webcrypto.

The WASM bindings default to a webworker implementation for broad compatibility with strict Content Security Policies. They may also be built as an ES6 module for direct calls, but that implementation may be blocked by several common `script-src` CSPs.

## Prerequisites
- A C++ compiler with support for cppstd 17 or higher
- CMake v3.16 or higher
- Conan v2.0 or higher configured to use your C++ compiler
- npm (optional, for test webpage)

## Build
### Build from source
```bash
conan install . -pr:h=profiles/emscripten-wasm --build=missing
conan build . -pr:h=profiles/emscripten-wasm
```

The resulting `openssl_wasm.js` and `openssl_wasm.wasm` artifacts can be found under `build/Release`.

#### ES6 Module Option
Append `-o modularize=True` to the above commands to build the wasm bindings as an ES6 module.

### Advanced Usage
The `conanfile.py` recipe can be exported to self-hosted conan indexes for automated build and deployment (ie using `conan create` or using deployer arguments with `conan install`). Supported versions can be found in `conandata.yml`.

## Usage
The wasm interface is synchronous and has the following spec:
```typescript
type SymmetricCipherArgs = {
    key: Uint8Array;
    iv?: Uint8Array;
    aad?: Uint8Array;
    tag?: Uint8Array;
}
interface OpensslWasmBindings {
    generateRandomBytes: (numBytes: number) => Uint8Array;
    symmetricKeygen: (algorithm: string) => Uint8Array;
    symmetricEncrypt: (algorithm: string, args: SymmetricCipherArgs, plaintext: Uint8Array) => { ciphertext: Uint8Array; tag?: Uint8Array };
    symmetricDecrypt: (algorithm: string, args: SymmetricCipherArgs, ciphertext: Uint8Array) => Uint8Array;
    symmetricAlgorithms: () => string[];
    pqcKeygen: (algorithm: string) => { publicKey: Uint8Array; privateKey: Uint8Array };
    pqcEncapsulate: (algorithm: string, publicKey: Uint8Array) => { ciphertext: Uint8Array; sharedSecret: Uint8Array };
    pqcDecapsulate: (algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array) => Uint8Array;
    pqcAlgorithms: () => string[];
}
```
The `demo` directory contains async typescript wrappers for both types of bindings and a demonstration webpage for reference purposes. The page is hosted at `localhost:3000` and can be deployed as follows:
```bash
cd demo
npm install
# Webworker
npm run build
npm run start
# ES6
npm run build-es6
npm run start-es6
```

## Capabilities
**Symmetric Algorithms:**
- AES GCM (aes-128-gcm, aes-192-gcm, aes-256-gcm)
- AES CBC (aes-128-cbc, aes-192-cbc, aes-256-cbc)
- AES CTR (aes-128-ctr, aes-192-ctr, aes-256-ctr)
- chacha20-poly1305

**PQC Algorithms:**
- ML-KEM (ML-KEM-512, ML-KEM-768, ML-KEM-1024)

**Asymmetric algorithms and signing algorithms are currently not supported.**