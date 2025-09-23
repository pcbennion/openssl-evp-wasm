type SymmetricCipherArgs = {
    key: Uint8Array;
    iv?: Uint8Array;
    aad?: Uint8Array;
    tag?: Uint8Array;
}

function ensureSymmetricCipherArgs(args: SymmetricCipherArgs) {
    return {
        key: args.key,
        iv: args.iv ?? undefined,
        aad: args.aad ?? undefined,
        tag: args.tag ?? undefined,
    };
}

export interface IOpensslEVP {
    generateRandomBytes(numBytes: number): Promise<Uint8Array>;
    symmetric: {
        keygen(algorithm: string): Promise<Uint8Array>;
        encrypt(algorithm: string, args: SymmetricCipherArgs, plaintext: Uint8Array): Promise<{ ciphertext: Uint8Array; tag?: Uint8Array }>;
        decrypt(algorithm: string, args: SymmetricCipherArgs, ciphertext: Uint8Array): Promise<Uint8Array>;
        algorithms(): string[];
    };
    pqc: {
        keygen(algorithm: string): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
        encapsulate(algorithm: string, publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>;
        decapsulate(algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
        algorithms(): string[];
    };
}

interface OpensslWasmBindings {
    generateRandomBytes: (numBytes: number) => Uint8Array;
    symmetricKeygen: (algorithm: string) => Uint8Array;
    symmetricEncrypt: (algorithm: string, args: SymmetricCipherArgs, plaintext: Uint8Array) => { ciphertext: Uint8Array; tag?: Uint8Array };
    symmetricDecrypt: (algorithm: string, args: SymmetricCipherArgs, ciphertext: Uint8Array) => Uint8Array;
    symmetricAlgorithms: () => string[];
    pqcKeygen: (algorithm: string) => { publicKey: Uint8Array; privateKey: Uint8Array };
    pqcEncapsulate: (algorithm: string, publicKey: Uint8Array) => { ciphertext: Uint8Array; sharedSecret: Uint8Array };
    pqcDecapsulate: (algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array) => Uint8Array;
    pqcAlgorithms: () => string[];
}
interface ES6Module {
    default: () => Promise<OpensslWasmBindings>;
}

export class OpensslEVPModule implements IOpensslEVP {
    private _bindings: OpensslWasmBindings | undefined;
    private get bindings(): OpensslWasmBindings {
        if (!this._bindings) {
            throw new Error('WASM bindings not initialized');
        }
        return this._bindings;
    }

    symmetric: IOpensslEVP['symmetric'];
    pqc: IOpensslEVP['pqc'];
    constructor() {
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
            encrypt: (algorithm: string, args: SymmetricCipherArgs, plaintext: Uint8Array) => {
                return new Promise((resolve, reject) => {
                    try {
                        const result = this.bindings.symmetricEncrypt(algorithm, ensureSymmetricCipherArgs(args), plaintext);
                        resolve(result);
                    } catch (e) {
                        reject(e);
                    }
                });
            },
            decrypt: (algorithm: string, args: SymmetricCipherArgs, ciphertext: Uint8Array) => {
                return new Promise((resolve, reject) => {
                    try {
                        const result = this.bindings.symmetricDecrypt(algorithm, ensureSymmetricCipherArgs(args), ciphertext);
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

    async initialize(module: ES6Module) {
        this._bindings = await module.default();
        return this;
    }

    async generateRandomBytes(numBytes: number): Promise<Uint8Array> {
        return new Promise((resolve, reject) => {
            try {
                const result = this.bindings.generateRandomBytes(numBytes);
                resolve(result);
            } catch (e) {
                reject(e);
            }
        });
    }
}
