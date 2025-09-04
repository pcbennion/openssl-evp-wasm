export interface IOpensslEVP {
  // Asymmetric key generation (RSA, ECC, ML-KEM, etc.)
  generateAsymmetricKeyPair(algorithm: string): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };

  // Symmetric key generation (AES, etc.)
  generateSymmetricKey(algorithm: string, keyLength: number): Uint8Array;

  // PQC Encapsulation/Decapsulation (ML-KEM, etc.)
  encapsulate(algorithm: string, publicKey: Uint8Array): {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
  };
  decapsulate(algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;

  // Classical Encryption/Decryption (AES, RSA, etc.)
  encrypt(algorithm: string, key: Uint8Array, iv: Uint8Array | null, plaintext: Uint8Array): Uint8Array;
  decrypt(algorithm: string, key: Uint8Array, iv: Uint8Array | null, ciphertext: Uint8Array): Uint8Array;

  // Utility (optional)
  getSupportedAlgorithms(): string[];
}

export class OpensslEVP implements IOpensslEVP {
  private bindings: any;
  constructor() {}
  async load(wasmPath: string) {
    // Emscripten-generated WASM modules typically export a factory function
    // that returns a promise resolving to the module instance
    this.bindings = await (window as any)[wasmPath]();
  }

  generateAsymmetricKeyPair(algorithm: string) {
    return this.bindings.generateAsymmetricKeyPair(algorithm);
  }

  generateSymmetricKey(algorithm: string, keyLength: number) {
    return this.bindings.generateSymmetricKey(algorithm, keyLength);
  }

  encapsulate(algorithm: string, publicKey: Uint8Array) {
    return this.bindings.encapsulate(algorithm, publicKey);
  }

  decapsulate(algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array) {
    return this.bindings.decapsulate(algorithm, privateKey, ciphertext);
  }

  encrypt(algorithm: string, key: Uint8Array, iv: Uint8Array | null, plaintext: Uint8Array) {
    return this.bindings.encrypt(algorithm, key, iv, plaintext);
  }

  decrypt(algorithm: string, key: Uint8Array, iv: Uint8Array | null, ciphertext: Uint8Array) {
    return this.bindings.decrypt(algorithm, key, iv, ciphertext);
  }

  getSupportedAlgorithms() {
    return this.bindings.getSupportedAlgorithms();
  }
}