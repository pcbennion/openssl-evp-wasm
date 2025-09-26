#pragma once
#include "evp_wasm.h"


namespace evp::symmetric {

struct CipherData {
    size_t keyLength;
    size_t ivLength;
    size_t tagLength;
};

const std::map<std::string, CipherData> SupportedCiphers = {
    {"aes-128-gcm",        {16, 12, 16}},
    {"aes-192-gcm",        {24, 12, 16}},
    {"aes-256-gcm",        {32, 12, 16}},
    {"aes-128-cbc",        {16, 16, 0}},
    {"aes-192-cbc",        {24, 16, 0}},
    {"aes-256-cbc",        {32, 16, 0}},
    {"aes-128-ctr",        {16, 16, 0}},
    {"aes-192-ctr",        {24, 16, 0}},
    {"aes-256-ctr",        {32, 16, 0}},
    {"chacha20-poly1305",  {32, 12, 16}}
};

// Struct for additional data required by supported symmetric algorithms
struct CipherArgs {
    emscripten::val key;         // Key (required for all)
    emscripten::val iv;          // IV/nonce (required for most modes)
    emscripten::val aad;         // Additional Authenticated Data (AEAD only)
    emscripten::val tag;         // Auth tag (output for AEAD encrypt, input for AEAD decrypt)
};

struct CipherOutput {
    emscripten::val ciphertext;  // Encrypted data
    emscripten::val tag;         // Auth tag (for AEAD)
};

emscripten::val keygen(std::string algorithm);
CipherOutput encrypt(std::string algorithm, const CipherArgs& args, emscripten::val plaintext);
emscripten::val decrypt(std::string algorithm, const CipherArgs& args, emscripten::val ciphertext);
emscripten::val algorithms();

} // namespace evp::symmetric