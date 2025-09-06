#pragma once
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <emscripten/val.h>

namespace evp::pqc {

struct CipherData {
    size_t publicKeyLength;
    size_t privateKeyLength;
    size_t ciphertextLength;
    size_t secretLength;
};

const std::map<std::string, CipherData> SupportedCiphers = {
    {"ML-KEM-512",   {800, 1632, 768, 32}},
    {"ML-KEM-768",   {1184, 2400, 1088, 32}},
    {"ML-KEM-1024",  {1568, 3168, 1568, 32}},
};

struct KeygenOutput {
    emscripten::val publicKey;
    emscripten::val privateKey;
};

struct EncapOutput {
    emscripten::val ciphertext;
    emscripten::val sharedSecret;
};

KeygenOutput keygen(std::string algorithm);
EncapOutput encapsulate(std::string algorithm, emscripten::val publicKey);
emscripten::val decapsulate(std::string algorithm, emscripten::val privateKey, emscripten::val ciphertext);
emscripten::val algorithms();

} // namespace evp::pqc