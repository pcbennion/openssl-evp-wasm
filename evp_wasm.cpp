#include <stdexcept>
#include <openssl/rand.h>
#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "evp_symmetric.h"
#include "evp_pqc.h"

namespace evp {

emscripten::val generateRandomBytes(size_t length) {
    if (length == 0) {
        throw std::invalid_argument("Length must be greater than zero");
    }
    std::vector<uint8_t> buffer(length);
    if (RAND_bytes(buffer.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return vectorToUint8Array(buffer);
}

EMSCRIPTEN_BINDINGS(openssl_evp_wasm) {
    emscripten::function("generateRandomBytes", &generateRandomBytes);

    emscripten::value_object<symmetric::CipherArgs>("symmetricCipherArgs")
        .field("key", &symmetric::CipherArgs::key)
        .field("iv", &symmetric::CipherArgs::iv)
        .field("aad", &symmetric::CipherArgs::aad)
        .field("tag", &symmetric::CipherArgs::tag);

    emscripten::value_object<symmetric::CipherOutput>("symmetricCipherOutput")
        .field("ciphertext", &symmetric::CipherOutput::ciphertext)
        .field("tag", &symmetric::CipherOutput::tag);

    emscripten::function("symmetricKeygen", &symmetric::keygen);
    emscripten::function("symmetricEncrypt", &symmetric::encrypt);
    emscripten::function("symmetricDecrypt", &symmetric::decrypt);
    emscripten::function("symmetricAlgorithms", &symmetric::algorithms);

    emscripten::value_object<pqc::KeygenOutput>("pqcKeygenOutput")
        .field("publicKey", &pqc::KeygenOutput::publicKey)
        .field("privateKey", &pqc::KeygenOutput::privateKey);

    emscripten::value_object<pqc::EncapOutput>("pqcEncapOutput")
        .field("ciphertext", &pqc::EncapOutput::ciphertext)
        .field("sharedSecret", &pqc::EncapOutput::sharedSecret);

    emscripten::function("pqcKeygen", &pqc::keygen);
    emscripten::function("pqcEncapsulate", &pqc::encapsulate);
    emscripten::function("pqcDecapsulate", &pqc::decapsulate);
    emscripten::function("pqcAlgorithms", &pqc::algorithms);
}

}