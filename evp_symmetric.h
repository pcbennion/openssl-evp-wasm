#include <emscripten/val.h>

namespace evp {
namespace symmetric {

// Struct for additional data required by supported symmetric algorithms
struct CipherData {
    emscripten::val key;         // Key (required for all)
    emscripten::val iv;          // IV/nonce (required for most modes)
    emscripten::val aad;         // Additional Authenticated Data (AEAD only)
    emscripten::val tag;         // Auth tag (output for AEAD encrypt, input for AEAD decrypt)
    int tagLength = 16;          // Tag length (AEAD, e.g., GCM/CCM/OCB)
    int ccmL = 0;                // CCM L parameter (for AES-CCM)
    int ccmM = 0;                // CCM M parameter (for AES-CCM tag length)
    std::string algorithm;
};

struct CipherOutput {
    emscripten::val ciphertext;  // Encrypted data
    emscripten::val tag;         // Auth tag (for AEAD)
};

emscripten::val generateRandomBytes(size_t length);

enum class Cipher {
    UNKNOWN=-1,
    AES_128_GCM,
    AES_128_CBC,
    AES_128_CTR,
    AES_192_GCM,
    AES_192_CBC,
    AES_192_CTR,
    AES_256_GCM,
    AES_256_CBC,
    AES_256_CTR,
    CHACHA20_POLY1305
};
Cipher getCipher(const std::string& name);
size_t getCipherKeySize(Cipher cipher);

emscripten::val keygen(std::string cipher);
CipherOutput encrypt(const CipherData& algorithm, emscripten::val plaintext);
emscripten::val decrypt(const CipherData& algorithm, emscripten::val ciphertext);
emscripten::val algorithms();

}
}