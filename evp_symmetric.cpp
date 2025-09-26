#include "evp_symmetric.h"

namespace evp::symmetric {

static CipherData getCipherData(std::string algorithm) {
    auto it = SupportedCiphers.find(algorithm);
    if (it != SupportedCiphers.end()) return it->second;
    throw std::invalid_argument("Unsupported cipher");
}

emscripten::val keygen(std::string algorithm) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    size_t keyLength = getCipherData(algorithm).keyLength;
    std::vector<uint8_t> key(keyLength);
    if (RAND_bytes(key.data(), keyLength) != 1) {
        throw std::runtime_error("Failed to generate random symmetric key");
    }
    return vectorToUint8Array(key);
}

CipherOutput encrypt(std::string algorithm, const CipherArgs& args, emscripten::val plaintext) {
    const EVP_CIPHER* evpCipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!evpCipher) throw std::invalid_argument("Unknown cipher algorithm");
    const CipherData cipherData = getCipherData(algorithm);

    std::vector<uint8_t> plaintextVec = uint8ArrayToVector(plaintext);
    if (plaintextVec.empty()) {
        throw std::invalid_argument("Empty or invalid plaintext");
    }
    std::vector<uint8_t> keyVec = uint8ArrayToVector(args.key);
    if (keyVec.size() != cipherData.keyLength) {
        throw std::invalid_argument("Invalid key length");
    }
    std::vector<uint8_t> ivVec = uint8ArrayToVector(args.iv);
    if (ivVec.size() != cipherData.ivLength) {
        throw std::invalid_argument("Invalid IV length");
    }
    std::vector<uint8_t> aadVec = uint8ArrayToVector(args.aad);
    if ((!args.tag.isUndefined() || !args.tag.isNull()) && cipherData.tagLength > 0) {
        throw std::invalid_argument("Tag should not be provided for encryption");
    }
    std::vector<uint8_t> ciphertext(plaintextVec.size() + EVP_CIPHER_block_size(evpCipher));
    std::vector<uint8_t> tag(cipherData.tagLength);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    if (EVP_EncryptInit_ex(ctx, evpCipher, nullptr, keyVec.data(), ivVec.empty() ? nullptr : ivVec.data()) != 1) {
        throw std::runtime_error("EncryptInit failed");
    }
    if (cipherData.tagLength > 0 && !aadVec.empty()) {
        int aad_len = 0;
        if (EVP_EncryptUpdate(ctx, nullptr, &aad_len, aadVec.data(), aadVec.size()) != 1) {
            throw std::runtime_error("EncryptUpdate (AAD) failed");
        }
    }
    int out_len1 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintextVec.data(), plaintextVec.size()) != 1) {
        throw std::runtime_error("EncryptUpdate failed");
    }
    int out_len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1) {
        throw std::runtime_error("EncryptFinal failed");
    }
    ciphertext.resize(out_len1 + out_len2);
    if (cipherData.tagLength > 0 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, cipherData.tagLength, tag.data()) != 1) {
            throw std::runtime_error("Failed to get authentication tag");
    }
    EVP_CIPHER_CTX_free(ctx);
    return {vectorToUint8Array(ciphertext), vectorToUint8Array(tag)};
}

emscripten::val decrypt(std::string algorithm, const CipherArgs& args, emscripten::val ciphertext) {
    const EVP_CIPHER* evpCipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!evpCipher) throw std::invalid_argument("Unknown cipher algorithm");
    const CipherData cipherData = getCipherData(algorithm);

    std::vector<uint8_t> ciphertextVec = uint8ArrayToVector(ciphertext);
    if (ciphertextVec.empty()) {
        throw std::invalid_argument("Empty or invalid ciphertext");
    }
    std::vector<uint8_t> keyVec = uint8ArrayToVector(args.key);
    if (keyVec.size() != cipherData.keyLength) {
        throw std::invalid_argument("Invalid key length");
    }
    std::vector<uint8_t> ivVec = uint8ArrayToVector(args.iv);
    if (ivVec.size() != cipherData.ivLength) {
        throw std::invalid_argument("Invalid IV length");
    }
    std::vector<uint8_t> tagVec = uint8ArrayToVector(args.tag);
    if (tagVec.size() != cipherData.tagLength) {
        throw std::invalid_argument("Invalid tag length");
    }
    std::vector<uint8_t> aadVec = uint8ArrayToVector(args.aad);
    std::vector<uint8_t> plaintext(ciphertextVec.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    if (EVP_DecryptInit_ex(ctx, evpCipher, nullptr, keyVec.data(), ivVec.empty() ? nullptr : ivVec.data()) != 1) {
        throw std::runtime_error("DecryptInit failed");
    }

    if (cipherData.tagLength > 0 && !aadVec.empty()) {
        int aad_len = 0;
        if (EVP_DecryptUpdate(ctx, nullptr, &aad_len, aadVec.data(), aadVec.size()) != 1) {
            throw std::runtime_error("DecryptUpdate (AAD) failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, cipherData.tagLength, tagVec.data()) != 1) {
            throw std::runtime_error("Failed to set authentication tag");
        }
    }
    int out_len1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertextVec.data(), ciphertextVec.size()) != 1) {
        throw std::runtime_error("DecryptUpdate failed");
    }
    int out_len2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2) != 1) {
        throw std::runtime_error("DecryptFinal failed");
    }
    plaintext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return {vectorToUint8Array(plaintext)};
}

emscripten::val algorithms() {
    std::vector<std::string> algs;
    for (const auto& pair : SupportedCiphers) {
        algs.push_back(pair.first);
    }
    return emscripten::val::array(algs);
}

} // namespace evp::symmetric