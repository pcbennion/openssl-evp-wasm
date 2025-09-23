#include "evp_pqc.h"

namespace evp::pqc {

static CipherData getCipherData(std::string algorithm) {
    auto it = SupportedCiphers.find(algorithm);
    if (it != SupportedCiphers.end()) return it->second;
    throw std::invalid_argument("Unsupported cipher");
}

KeygenOutput keygen(std::string algorithm) {
    const CipherData cipherData = getCipherData(algorithm);
    size_t publicKeyLength = cipherData.publicKeyLength;
    size_t privateKeyLength = cipherData.privateKeyLength;

    std::vector<uint8_t> publicKey(publicKeyLength);
    std::vector<uint8_t> privateKey(privateKeyLength);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, algorithm.c_str(), nullptr);
    if (!pctx) {
        throw std::runtime_error("Failed to create PKEY context");
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to initialize keygen");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Key generation failed");
    }
    EVP_PKEY_CTX_free(pctx);

    size_t pubLen = publicKeyLength;
    if (EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &pubLen) <= 0 || pubLen != publicKeyLength) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to extract public key");
    }
    size_t privLen = privateKeyLength;
    if (EVP_PKEY_get_raw_private_key(pkey, privateKey.data(), &privLen) <= 0 || privLen != privateKeyLength) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to extract private key");
    }
    EVP_PKEY_free(pkey);

    return { vectorToUint8Array(publicKey), vectorToUint8Array(privateKey) };
}

EncapOutput encapsulate(std::string algorithm, emscripten::val publicKey) {
    const CipherData cipherData = getCipherData(algorithm);
    size_t publicKeyLength = cipherData.publicKeyLength;
    size_t ciphertextLength = cipherData.ciphertextLength;
    size_t secretLength = cipherData.secretLength;

    std::vector<uint8_t> publicKeyVec = uint8ArrayToVector(publicKey);
    if (publicKeyVec.size() != publicKeyLength) {
        throw std::invalid_argument("Invalid public key length");
    }
    std::vector<uint8_t> ciphertext(ciphertextLength);
    std::vector<uint8_t> sharedSecret(secretLength);

    EVP_PKEY* peerkey = EVP_PKEY_new_raw_public_key_ex(nullptr, algorithm.c_str(), nullptr, publicKeyVec.data(), publicKeyLength);
    if (!peerkey) {
        throw std::runtime_error("Failed to import public key");
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(peerkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peerkey);
        throw std::runtime_error("Failed to create PKEY context");
    }
    if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
        EVP_PKEY_free(peerkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encapsulation");
    }
    size_t ctLen = ciphertext.size();
    size_t ssLen = sharedSecret.size();
    if (EVP_PKEY_encapsulate(ctx, ciphertext.data(), &ctLen, sharedSecret.data(), &ssLen) <= 0) {
        EVP_PKEY_free(peerkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Encapsulation failed");
    }
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(ctx);

    ciphertext.resize(ctLen);
    sharedSecret.resize(ssLen);
    return { vectorToUint8Array(ciphertext), vectorToUint8Array(sharedSecret) };
}

emscripten::val decapsulate(std::string algorithm, emscripten::val privateKey, emscripten::val ciphertext) {
    const CipherData cipherData = getCipherData(algorithm);
    size_t privateKeyLength = cipherData.privateKeyLength;
    size_t ciphertextLength = cipherData.ciphertextLength;
    size_t secretLength = cipherData.secretLength;

    std::vector<uint8_t> privateKeyVec = uint8ArrayToVector(privateKey);
    if (privateKeyVec.size() != privateKeyLength) {
        throw std::invalid_argument("Invalid private key length");
    }
    std::vector<uint8_t> ciphertextVec = uint8ArrayToVector(ciphertext);
    if (ciphertextVec.size() != ciphertextLength) {
        throw std::invalid_argument("Invalid ciphertext length");
    }
    std::vector<uint8_t> sharedSecret(secretLength);

    EVP_PKEY* privkey = EVP_PKEY_new_raw_private_key_ex(nullptr, algorithm.c_str(), nullptr, privateKeyVec.data(), privateKeyLength);
    if (!privkey) {
        throw std::runtime_error("Failed to create private key");
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(privkey);
        throw std::runtime_error("Failed to create PKEY context");
    }
    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
        EVP_PKEY_free(privkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decapsulation");
    }
    size_t ssLen = sharedSecret.size();
    if (EVP_PKEY_decapsulate(ctx, sharedSecret.data(), &ssLen, ciphertextVec.data(), ciphertextVec.size()) <= 0) {
        EVP_PKEY_free(privkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Decapsulation failed");
    }
    EVP_PKEY_free(privkey);
    EVP_PKEY_CTX_free(ctx);

    sharedSecret.resize(ssLen);
    return vectorToUint8Array(sharedSecret);
}

emscripten::val algorithms() {
    std::vector<std::string> algs;
    for (const auto& pair : SupportedCiphers) {
        algs.push_back(pair.first);
    }
    return emscripten::val::array(algs);
}

} // namespace evp::pqc