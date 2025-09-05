type symmetricCipherArgs = {
    algorithm?: string;
    key?: Uint8Array;
    iv?: Uint8Array;
    plaintext?: Uint8Array;
}

export interface IOpensslEVP {
  symmetric: {
    keygen(algorithm: string): Promise<Uint8Array>;
    encrypt(algorithm: string, args: symmetricCipherArgs, plaintext: Uint8Array): Promise<{ ciphertext: Uint8Array, tag?: Uint8Array }>;
    decrypt(algorithm: string, args: symmetricCipherArgs, ciphertext: Uint8Array): Promise<Uint8Array>;
    algorithms(): string[];
  };
  pqc: {
    keygen(algorithm: string): Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>;
    encapsulate(algorithm: string, publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array, sharedSecret: Uint8Array }>;
    decapsulate(algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
    algorithms(): string[];
  };
}

export default class OpensslEVP implements IOpensslEVP {
  symmetric: IOpensslEVP['symmetric'];
  pqc: IOpensslEVP['pqc'];
  constructor(private bindings: any) {
    this.symmetric = {
      keygen: (algorithm: string) => {
        return new Promise((resolve, reject) => {
          try {
            const result = this.bindings.symmetricKeygen(algorithm);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
      encrypt: (algorithm: string, args: symmetricCipherArgs, plaintext: Uint8Array) => {
        return new Promise((resolve, reject) => {
          try {
            const result = this.bindings.symmetricEncrypt(algorithm, args, plaintext);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
      decrypt: (algorithm: string, args: symmetricCipherArgs, ciphertext: Uint8Array) => {
        return new Promise((resolve, reject) => {
          try {
            const result = this.bindings.symmetricDecrypt(algorithm, args, ciphertext);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
      algorithms: () => {
        return this.bindings.symmetricAlgorithms();
      },
    };

    this.pqc = {
      keygen: (algorithm: string) => {
        return new Promise((resolve, reject) => {
          try {
            const result = this.bindings.pqcKeygen(algorithm);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
      encapsulate: (algorithm: string, publicKey: Uint8Array) => {
        return new Promise((resolve, reject) => {
          try {
            const result = this.bindings.pqcEncapsulate(algorithm, publicKey);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
      decapsulate: (algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array) => {
        return new Promise((resolve, reject) => {
          try {
            const result = this.bindings.pqcDecapsulate(algorithm, privateKey, ciphertext);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        });
      },
      algorithms: () => {
        return this.bindings.pqcAlgorithms();
      },
    };
  }
}