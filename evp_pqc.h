#pragma once
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <emscripten/val.h>

namespace evp::pqc {

struct CipherData {
    int pkeyType;
    size_t publicKeyLength;
    size_t privateKeyLength;
    size_t ciphertextLength;
    size_t secretLength;
};

const std::map<std::string, CipherData> SupportedCiphers = {
    {"KYBER512",   {EVP_PKEY_KYBER512, 800, 1632, 32}},
    {"KYBER768",   {EVP_PKEY_KYBER768, 1184, 2400, 32}},
    {"KYBER1024",  {EVP_PKEY_KYBER1024, 1568, 3168, 32}},
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