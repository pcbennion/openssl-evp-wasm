#include <emscripten/bind.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdexcept>

inline unsigned char* vec_to_uchar(std::vector<uint8_t>& v) {
    return v.empty() ? nullptr : &v[0];
}

struct KeyPair {
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;
};

struct EncapsulatedKey {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> sharedSecret;
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
        if (EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, 2048, nullptr) <= 0) {
            throw std::runtime_error("Failed to set RSA bits");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            throw std::runtime_error("Failed to generate RSA keypair");
        }

        // Extract keys in DER format
        int pub_len = i2d_PUBKEY(pkey, nullptr);
        int priv_len = i2d_PrivateKey(pkey, nullptr);
        kp.publicKey.resize(pub_len);
        kp.privateKey.resize(priv_len);

        unsigned char* pub_ptr = kp.publicKey.data();
        unsigned char* priv_ptr = kp.privateKey.data();
        i2d_PUBKEY(pkey, &pub_ptr);
        i2d_PrivateKey(pkey, &priv_ptr);

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
    } else {
        throw std::runtime_error("Unsupported algorithm for asymmetric key generation");
    }
    return kp;
}

// Symmetric key generation using OpenSSL RNG
std::vector<uint8_t> generateSymmetricKey(const std::string& algorithm, int keyLength) {
    std::vector<uint8_t> key(keyLength);
    if (RAND_bytes(key.data(), keyLength) != 1) {
        throw std::runtime_error("Failed to generate random symmetric key");
    }
    return key;
}

// Placeholder for PQC encapsulation/decapsulation (not supported by OpenSSL EVP)
EncapsulatedKey encapsulate(const std::string& algorithm, const std::vector<uint8_t>& publicKey) {
    throw std::runtime_error("Encapsulation not implemented for this algorithm");
}

std::vector<uint8_t> decapsulate(const std::string& algorithm, const std::vector<uint8_t>& privateKey, const std::vector<uint8_t>& ciphertext) {
    throw std::runtime_error("Decapsulation not implemented for this algorithm");
}

// Classical Encryption (AES example)
std::vector<uint8_t> encrypt(const std::string& algorithm, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& plaintext) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!cipher) throw std::runtime_error("Unknown cipher algorithm");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.empty() ? nullptr : iv.data()) != 1)
        throw std::runtime_error("EncryptInit failed");

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_block_size(cipher));
    int out_len1 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintext.data(), plaintext.size()) != 1)
        throw std::runtime_error("EncryptUpdate failed");

    int out_len2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1)
        throw std::runtime_error("EncryptFinal failed");

    ciphertext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Classical Decryption (AES example)
std::vector<uint8_t> decrypt(const std::string& algorithm, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& ciphertext) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (!cipher) throw std::runtime_error("Unknown cipher algorithm");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.empty() ? nullptr : iv.data()) != 1)
        throw std::runtime_error("DecryptInit failed");

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext.data(), ciphertext.size()) != 1)
        throw std::runtime_error("DecryptUpdate failed");

    int out_len2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2) != 1)
        throw std::runtime_error("DecryptFinal failed");

    plaintext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// Utility: get supported algorithms (AES and RSA for demo)
std::vector<std::string> getSupportedAlgorithms() {
    return {"AES-128-CBC", "AES-256-CBC", "RSA"};
}

// Emscripten bindings
EMSCRIPTEN_BINDINGS(openssl_evp_wasm) {
    emscripten::value_array<KeyPair>("KeyPair")
        .element(&KeyPair::publicKey)
        .element(&KeyPair::privateKey);

    emscripten::value_array<EncapsulatedKey>("EncapsulatedKey")
        .element(&EncapsulatedKey::ciphertext)
        .element(&EncapsulatedKey::sharedSecret);

    emscripten::function("generateAsymmetricKeyPair", &generateAsymmetricKeyPair);
    emscripten::function("generateSymmetricKey", &generateSymmetricKey);
    emscripten::function("encapsulate", &encapsulate);
    emscripten::function("decapsulate", &decapsulate);
    emscripten::function("encrypt", &encrypt);
    emscripten::function("decrypt", &decrypt);
    emscripten::function("getSupportedAlgorithms", &getSupportedAlgorithms);
}
