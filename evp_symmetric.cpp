#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <map>

#include "evp_symmetric.h"

namespace evp {
namespace symmetric {

static const std::map<std::string, Cipher> stringToCipher = {
    {"AES-128-GCM", Cipher::AES_128_GCM},
    {"AES-192-GCM", Cipher::AES_192_GCM},
    {"AES-256-GCM", Cipher::AES_256_GCM},
    {"AES-128-CBC", Cipher::AES_128_CBC},
    {"AES-192-CBC", Cipher::AES_192_CBC},
    {"AES-256-CBC", Cipher::AES_256_CBC},
    {"AES-128-CTR", Cipher::AES_128_CTR},
    {"AES-192-CTR", Cipher::AES_192_CTR},
    {"AES-256-CTR", Cipher::AES_256_CTR},
    {"CHACHA20-POLY1305", Cipher::CHACHA20_POLY1305},
};
Cipher getCipher(const std::string& name) {
    auto it = stringToCipher.find(name);
    if (it != stringToCipher.end()) return it->second;
    return Cipher::UNKNOWN;
}
size_t getCipherKeySize(Cipher cipher) {
    switch (cipher) {
        case Cipher::AES_128_GCM:
        case Cipher::AES_128_CBC:
        case Cipher::AES_128_CTR: 
            return 16;
        case Cipher::AES_192_GCM:
        case Cipher::AES_192_CBC:
        case Cipher::AES_192_CTR: 
            return 24;
        case Cipher::AES_256_GCM:
        case Cipher::AES_256_CBC:
        case Cipher::AES_256_CTR:
        case Cipher::CHACHA20_POLY1305:
            return 32;
        default: 
            throw std::invalid_argument("Unsupported cipher");
    }
}

emscripten::val keygen(std::string cipher) {
    size_t keyLength = getCipherKeySize(getCipher(cipher));
    std::vector<uint8_t> key(keyLength);
    if (RAND_bytes(key.data(), keyLength) != 1) {
        throw std::runtime_error("Failed to generate random symmetric key");
    }
    return emscripten::val::array(key);
}

CipherOutput encrypt(const CipherData& algorithm, emscripten::val plaintext) {
    // Encryption logic
}

emscripten::val decrypt(const CipherData& algorithm, emscripten::val ciphertext) {
    // Decryption logic
}

emscripten::val algorithms() {
    // Return supported algorithms
}

}
}