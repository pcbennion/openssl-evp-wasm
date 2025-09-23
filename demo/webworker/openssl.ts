import { WasmWorker } from "./worker";

type SymmetricCipherArgs = {
    key: Uint8Array;
    iv?: Uint8Array;
    aad?: Uint8Array;
    tag?: Uint8Array;
};

export interface IOpensslEVP {
    generateRandomBytes(numBytes: number): Promise<Uint8Array>;
    symmetric: {
        keygen(algorithm: string): Promise<Uint8Array>;
        encrypt(algorithm: string, args: SymmetricCipherArgs, plaintext: Uint8Array): Promise<{ ciphertext: Uint8Array; tag?: Uint8Array }>;
        decrypt(algorithm: string, args: SymmetricCipherArgs, ciphertext: Uint8Array): Promise<Uint8Array>;
        algorithms(): Promise<string[]>;
    };
    pqc: {
        keygen(algorithm: string): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
        encapsulate(algorithm: string, publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>;
        decapsulate(algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
        algorithms(): Promise<string[]>;
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

export class OpensslEVPWorker implements IOpensslEVP {
    private worker: WasmWorker;
    symmetric: IOpensslEVP['symmetric'];
    pqc: IOpensslEVP['pqc'];
    constructor(worker: Worker) {
        this.worker = new WasmWorker(worker);
        this.symmetric = {
            keygen: async (algorithm: string) => {
                const result = await this.worker.sendRequest(
                    'symmetricKeygen',
                    { algorithm }
                );
                if (!result || !('key' in result) || !(result.key instanceof Uint8Array)) {
                    throw new Error('WebWorker did not return a valid result!');
                }
                return result.key;
            },
            encrypt: async (algorithm: string, args: SymmetricCipherArgs, plaintext: Uint8Array) => {
                const result = await this.worker.sendRequest(
                    'symmetricEncrypt',
                    { algorithm, args, plaintext },
                    [args.key.buffer]
                );
                if (
                    !result || 
                    !('ciphertext' in result) || !(result.ciphertext instanceof Uint8Array) ||
                    !(!('tag' in result) || result.tag instanceof Uint8Array)
                ) {
                    throw new Error('WebWorker did not return a valid result!');
                }
                return result;
            },
            decrypt: async (algorithm: string, args: SymmetricCipherArgs, ciphertext: Uint8Array) => {
                const result = await this.worker.sendRequest(
                    'symmetricDecrypt',
                    { algorithm, args, ciphertext },
                    [args.key.buffer]
                );
                if (!result || !('plaintext' in result) || !(result.plaintext instanceof Uint8Array)) {
                    throw new Error('WebWorker did not return a valid result!');
                }
                return result.plaintext;
            },
            algorithms: async () => {
                const result = await this.worker.sendRequest(
                    'symmetricAlgorithms',
                    {},
                );
                return result.algorithms as string[];
            },
        };
        this.pqc = {
            keygen: async (algorithm: string) => {
                const result = await this.worker.sendRequest(
                    'pqcKeygen',
                    { algorithm },
                );
                if (
                    !result || 
                    !('publicKey' in result) || !(result.publicKey instanceof Uint8Array) ||
                    !('privateKey' in result) || !(result.privateKey instanceof Uint8Array)
                ) {
                    return new Error('WebWorker did not return a valid result!');
                }
                return result;
            },
            encapsulate: async (algorithm: string, publicKey: Uint8Array) => {
                const result = await this.worker.sendRequest(
                    'pqcEncapsulate',
                    { algorithm, publicKey },
                );
                if (
                    !result || 
                    !('ciphertext' in result) || !(result.ciphertext instanceof Uint8Array) ||
                    !('sharedSecret' in result) || !(result.sharedSecret instanceof Uint8Array)
                ) {
                    return new Error('WebWorker did not return a valid result!');
                }
                return result;
            },
            decapsulate: async (algorithm: string, privateKey: Uint8Array, ciphertext: Uint8Array) => {
                const result = await this.worker.sendRequest(
                    'pqcDecapsulate',
                    { algorithm, privateKey, ciphertext },
                    [privateKey.buffer]
                );
                if (!result || !('sharedSecret' in result) || !(result.sharedSecret instanceof Uint8Array)) {
                    throw new Error('WebWorker did not return a valid result!');
                }
                return result.sharedSecret;
            },
            algorithms: async () => {
                const result = await this.worker.sendRequest(
                    'pqcAlgorithms',
                    {},
                );
                return result.algorithms as string[];
            },
        };
    }

    async generateRandomBytes(numBytes: number): Promise<Uint8Array> {
        const result = await this.worker.sendRequest(
            'generateRandomBytes',
            { numBytes },
        );
        if (!result.bytes || !(result.bytes instanceof Uint8Array)) {
            throw new Error('WebWorker did not return a valid result!');
        }
        return result.bytes;
    }
}
