#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdexcept>

#include <iostream>

enum class SymmetricCipher {
    AES_128_GCM,
    AES_192_GCM,
    AES_256_GCM,
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC,
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
    CHACHA20_POLY1305,
    UNKNOWN
};
static const std::map<std::string, SymmetricCipher> stringToSymCipher = {
    {"AES-128-GCM", SymmetricCipher::AES_128_GCM},
    {"AES-192-GCM", SymmetricCipher::AES_192_GCM},
    {"AES-256-GCM", SymmetricCipher::AES_256_GCM},
    {"AES-128-CBC", SymmetricCipher::AES_128_CBC},
    {"AES-192-CBC", SymmetricCipher::AES_192_CBC},
    {"AES-256-CBC", SymmetricCipher::AES_256_CBC},
    {"AES-128-CTR", SymmetricCipher::AES_128_CTR},
    {"AES-192-CTR", SymmetricCipher::AES_192_CTR},
    {"AES-256-CTR", SymmetricCipher::AES_256_CTR},
    {"CHACHA20-POLY1305", SymmetricCipher::CHACHA20_POLY1305},
};
SymmetricCipher getSymCipher(const std::string& name) {
    auto it = stringToSymCipher.find(name);
    if (it != stringToSymCipher.end()) return it->second;
    return SymmetricCipher::UNKNOWN;
}

struct KeyPair {
    emscripten::val publicKey;
    emscripten::val privateKey;
};

struct EncapsulatedKey {
    emscripten::val ciphertext;
    emscripten::val sharedSecret;
};

// Asymmetric key generation (RSA example)
KeyPair generateAsymmetricKeyPair(const std::string& algorithm) {
    KeyPair kp;
    if (algorithm == "RSA") {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create RSA context");
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            throw std::runtime_error("Failed to init RSA keygen");
        }
        if (EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, 512, nullptr) <= 0) {
            throw std::runtime_error("Failed to set RSA bits");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            throw std::runtime_error("Failed to generate RSA keypair");
        }

        // Extract keys in DER format
        int pub_len = i2d_PUBKEY(pkey, nullptr);
        std::vector<uint8_t> pub_key(pub_len);
        int priv_len = i2d_PrivateKey(pkey, nullptr);
        std::vector<uint8_t> priv_key(priv_len);

        unsigned char* pub_ptr = pub_key.data();
        unsigned char* priv_ptr = priv_key.data();
        i2d_PUBKEY(pkey, &pub_ptr);
        i2d_PrivateKey(pkey, &priv_ptr);

        kp.publicKey = emscripten::val::array(pub_key);
        kp.privateKey = emscripten::val::array(priv_key);

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
    } else {
        throw std::runtime_error("Unsupported algorithm for asymmetric key generation");
    }
    return kp;
}

// Symmetric key generation using OpenSSL RNG
emscripten::val generateSymmetricKey(const std::string& algorithm, int keyLength) {
    std::vector<uint8_t> key(keyLength);
    if (RAND_bytes(key.data(), keyLength) != 1) {
        throw std::runtime_error("Failed to generate random symmetric key");
    }
    return emscripten::val::array(key);
}

// Placeholder for PQC encapsulation/decapsulation (not supported by OpenSSL EVP)
EncapsulatedKey encapsulate(const std::string& algorithm, const emscripten::val& publicKey) {
    throw std::runtime_error("Encapsulation not implemented for this algorithm");
}

emscripten::val decapsulate(const std::string& algorithm, const emscripten::val& privateKey, const emscripten::val& ciphertext) {
    throw std::runtime_error("Decapsulation not implemented for this algorithm");
}

// Symmetric Encryption
emscripten::val symmetricEncrypt(const std::string& algorithm, const emscripten::val& key, const emscripten::val& iv, const emscripten::val& plaintext) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!cipher) throw std::runtime_error("Unknown cipher algorithm");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    std::vector<uint8_t> keyVec = emscripten::vecFromJSArray<uint8_t>(key);
    std::vector<uint8_t> ivVec = emscripten::vecFromJSArray<uint8_t>(iv);
    std::vector<uint8_t> plaintextVec = emscripten::vecFromJSArray<uint8_t>(plaintext);

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, keyVec.data(), ivVec.empty() ? nullptr : ivVec.data()) != 1)
        throw std::runtime_error("EncryptInit failed");

    std::vector<uint8_t> ciphertext(plaintextVec.size() + EVP_CIPHER_block_size(cipher));
    int out_len1 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintextVec.data(), plaintextVec.size()) != 1)
        throw std::runtime_error("EncryptUpdate failed");

    int out_len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1)
        throw std::runtime_error("EncryptFinal failed");

    ciphertext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return emscripten::val::array(ciphertext);
}

// Symmetric Decryption
emscripten::val symmetricDecrypt(const std::string& algorithm, const emscripten::val& key, const emscripten::val& iv, const emscripten::val& ciphertext) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!cipher) throw std::runtime_error("Unknown cipher algorithm");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    std::vector<uint8_t> keyVec = emscripten::vecFromJSArray<uint8_t>(key);
    std::vector<uint8_t> ivVec = emscripten::vecFromJSArray<uint8_t>(iv);
    std::vector<uint8_t> ciphertextVec = emscripten::vecFromJSArray<uint8_t>(ciphertext);

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, keyVec.data(), ivVec.empty() ? nullptr : ivVec.data()) != 1)
        throw std::runtime_error("DecryptInit failed");

    std::vector<uint8_t> plaintext(ciphertextVec.size());
    int out_len1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertextVec.data(), ciphertextVec.size()) != 1)
        throw std::runtime_error("DecryptUpdate failed");

    int out_len2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2) != 1)
        throw std::runtime_error("DecryptFinal failed");

    plaintext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return emscripten::val::array(plaintext);
}



// Utility: get supported algorithms (AES and RSA for demo)
std::vector<std::string> getSupportedAlgorithms() {
    return {"AES-128-CBC", "AES-256-CBC", "RSA"};
}

// Asymmetric Encryption (RSA example)
emscripten::val asymmetricEncrypt(const std::string& algorithm, const emscripten::val& publicKey, const emscripten::val& plaintext) {
    if (algorithm != "RSA") {
        throw std::runtime_error("Only RSA supported for asymmetricEncrypt");
    }
    std::vector<uint8_t> pubKeyVec = emscripten::vecFromJSArray<uint8_t>(publicKey);
    std::vector<uint8_t> plaintextVec = emscripten::vecFromJSArray<uint8_t>(plaintext);

    const unsigned char* pubPtr = pubKeyVec.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &pubPtr, pubKeyVec.size());
    if (!pkey) {
        throw std::runtime_error("Failed to parse public key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create context");
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encrypt init failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintextVec.data(), plaintextVec.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encrypt size query failed");
    }
    std::vector<uint8_t> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintextVec.data(), plaintextVec.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encrypt failed");
    }
    ciphertext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return emscripten::val::array(ciphertext);
}

// Asymmetric Decryption (RSA example)
emscripten::val asymmetricDecrypt(const std::string& algorithm, const emscripten::val& privateKey, const emscripten::val& ciphertext) {
    if (algorithm != "RSA") {
        throw std::runtime_error("Only RSA supported for asymmetricDecrypt");
    }
    std::vector<uint8_t> privKeyVec = emscripten::vecFromJSArray<uint8_t>(privateKey);
    std::vector<uint8_t> ciphertextVec = emscripten::vecFromJSArray<uint8_t>(ciphertext);

    const unsigned char* privPtr = privKeyVec.data();
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &privPtr, privKeyVec.size());
    if (!pkey) {
        throw std::runtime_error("Failed to parse private key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create context");
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decrypt init failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertextVec.data(), ciphertextVec.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decrypt size query failed");
    }
    std::vector<uint8_t> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertextVec.data(), ciphertextVec.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decrypt failed");
    }
    plaintext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return emscripten::val::array(plaintext);
}

// Emscripten bindings
EMSCRIPTEN_BINDINGS(openssl_evp_wasm) {
    emscripten::value_object<>("")

    emscripten::value_object<KeyPair>("KeyPair")
        .field("publicKey", &KeyPair::publicKey)
        .field("privateKey", &KeyPair::privateKey);

    emscripten::value_object<EncapsulatedKey>("EncapsulatedKey")
        .field("ciphertext", &EncapsulatedKey::ciphertext)
        .field("sharedSecret", &EncapsulatedKey::sharedSecret);

    emscripten::function("generateAsymmetricKeyPair", &generateAsymmetricKeyPair);
    emscripten::function("generateSymmetricKey", &generateSymmetricKey);
    emscripten::function("encapsulate", &encapsulate);
    emscripten::function("decapsulate", &decapsulate);
    emscripten::function("encrypt", &encrypt);
    emscripten::function("decrypt", &decrypt);
    emscripten::function("getSupportedAlgorithms", &getSupportedAlgorithms);

    emscripten::function("asymmetricEncrypt", &asymmetricEncrypt);
    emscripten::function("asymmetricDecrypt", &asymmetricDecrypt);
}
