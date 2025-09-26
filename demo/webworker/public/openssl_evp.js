"use strict";

let runtimeLoaded = false;
async function importRuntime() {
    console.log('Importing runtime');
    importScripts('./openssl_wasm.js');
    Module.onRuntimeInitialized = () => {
        console.log("Openssl WASM module loaded");
        runtimeLoaded = true;
    }
}
importRuntime();

const waitUntil = (condition, checkInterval = 100) => {
    return new Promise((resolve) => {
        let interval = setInterval(() => {
            if (!condition()) return;
            clearInterval(interval);
            resolve();
        }, checkInterval);
    });
};

const ensureSymmetricCipherArgs = (args) => {
    return {
        key: args.key,
        iv: args.iv ?? undefined,
        aad: args.aad ?? undefined,
        tag: args.tag ?? undefined,
    };
}

class OpensslEVPClient {
    checkModule() {
        if (typeof Module !== "object") {
            throw new Error(
                "Global WASM Module object not found. Ensure WASM binary is fully loaded before calling this function"
            );
        }
    }
    getBinding(fname) {
        this.checkModule();
        const possibleFunction = Module[fname];
        if (typeof possibleFunction !== "function") {
            throw new Error(`function ${possibleFunction} not found!`);
        }
        return possibleFunction;
    }
    handleException(e) {
        try {
            const cpp_error = Module.getExceptionMessage(e)
            return {"error": cpp_error};
        }
        catch (not_cpp_error) {
            return {"error": e};
        }
    }

    constructor() {
        this.symmetric = {
            keygen: (algorithm) => {
                try {
                    const key = this.getBinding('symmetricKeygen')(algorithm);
                    return { result: { key }, transfer: key.buffer };
                } catch (e) {
                    return this.handleException(e);
                }
            },
            encrypt: (algorithm, args, plaintext) => {
                try {
                    const result = this.getBinding('symmetricEncrypt')(algorithm, ensureSymmetricCipherArgs(args), plaintext);
                    return { result };
                } catch (e) {
                    return this.handleException(e);
                }
            },
            decrypt: (algorithm, args, ciphertext) => {
                try {
                    const plaintext = this.getBinding('symmetricDecrypt')(algorithm, ensureSymmetricCipherArgs(args), ciphertext);
                    return { result: { plaintext } };
                } catch (e) {
                    return this.handleException(e);
                }
            },
            algorithms: () => {
                try {
                    const algorithms = this.getBinding('symmetricAlgorithms')();
                    return { result: { algorithms } };
                } catch (e) {
                    return this.handleException(e);
                }
            },
        };
        this.pqc = {
            keygen: (algorithm) => {
                try {
                    const result = this.getBinding('pqcKeygen')(algorithm);
                    return { result, transfer: result.privateKey.buffer };
                } catch (e) {
                    return this.handleException(e);
                }
            },
            encapsulate: (algorithm, publicKey) => {
                try {
                    const result = this.getBinding('pqcEncapsulate')(algorithm, publicKey);
                    return { result, transfer: result.sharedSecret.buffer };
                } catch (e) {
                    return this.handleException(e);
                }
            },
            decapsulate: (algorithm, privateKey, ciphertext) => {
                try {
                    const sharedSecret = this.getBinding('pqcDecapsulate')(algorithm, privateKey, ciphertext);
                    return { result: { sharedSecret }, transfer: sharedSecret.buffer };
                } catch (e) {
                    return this.handleException(e);
                }
            },
            algorithms: () => {
                try {
                    const algorithms = this.getBinding('pqcAlgorithms')();
                    return { result: { algorithms } };
                } catch (e) {
                    return this.handleException(e);
                }
            },
        };
    }

    generateRandomBytes(numBytes) {
        try {
            const bytes = this.getBinding('generateRandomBytes')(numBytes);
            return { result: { bytes }, transfer: bytes.buffer };
        } catch (e) {
            return this.handleException(e);
        }
    }
}

const client = new OpensslEVPClient();
const eventHandlers = {
    'symmetricKeygen': (data) => client.symmetric.keygen(data.algorithm),
    'symmetricEncrypt': (data) => client.symmetric.encrypt(data.algorithm, data.args, data.plaintext),
    'symmetricDecrypt': (data) => client.symmetric.decrypt(data.algorithm, data.args, data.ciphertext),
    'symmetricAlgorithms': () => client.symmetric.algorithms(),
    'pqcKeygen': (data) => client.pqc.keygen(data.algorithm),
    'pqcEncapsulate': (data) => client.pqc.encapsulate(data.algorithm, data.publicKey),
    'pqcDecapsulate': (data) => client.pqc.decapsulate(data.algorithm, data.privateKey, data.ciphertext),
    'pqcAlgorithms': () => client.pqc.algorithms(),
    'generateRandomBytes': (data) => client.generateRandomBytes(data.numBytes),
};
onmessage = (ev) => {
    const data = ev.data;
    const id = data.id;
    waitUntil(() => runtimeLoaded).then(() => {
        const handler = eventHandlers[data.event];
        if (!handler) {
            console.error(`Unknown event: ${data.event}`);
            return;
        }
        Promise.resolve(handler(data)).then(({ result, transfer, error }) => {
            postMessage({ id, result, error }, (transfer ? [transfer] : []));
        }).catch(error => {
            postMessage({ id, error });
        });
    });
};
