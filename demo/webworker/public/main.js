import { OpensslEVPWorker } from './bundle.js';

let evp;
window.onload = async function() {
    const workerURL = window.origin.concat('/openssl_evp.js');
    evp = new OpensslEVPWorker(new Worker(workerURL));

    // Populate sym-alg combo box
    const symAlgSelect = document.getElementById('sym-alg');
    const algs = await evp.symmetric.algorithms();
    symAlgSelect.innerHTML = '';
    algs.forEach(alg => {
        const opt = document.createElement('option');
        opt.value = alg;
        opt.textContent = alg;
        symAlgSelect.appendChild(opt);
    });

    // Populate pqc-alg combo box
    const pqcAlgSelect = document.getElementById('pqc-alg');
    const pqcAlgs = await evp.pqc.algorithms();
    pqcAlgSelect.innerHTML = '';
    pqcAlgs.forEach(alg => {
        const opt = document.createElement('option');
        opt.value = alg;
        opt.textContent = alg;
        pqcAlgSelect.appendChild(opt);
    });
}

function copyToClipboard(id) {
    const el = document.getElementById(id);
    el.select();
    navigator.clipboard.writeText(el.value);
}
function pasteFromClipboard(id) {
    navigator.clipboard.readText().then(text => {
        document.getElementById(id).value = text;
    });
}
function b64ToArray(str) {
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
function arrayToB64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}
async function generateBytesHelper(numBytes) {
    try {
        const retval = await evp.generateRandomBytes(numBytes);
        return arrayToB64(retval);
    } catch(err) {
        return 'Error: ' + err;
    }
}
async function generateBytes() {
    const numBytes = parseInt(document.getElementById('gen-len').value);
    document.getElementById('gen-output').value = await generateBytesHelper(numBytes);
}
async function symEncrypt() {
    const alg = document.getElementById('sym-alg').value;
    const key = b64ToArray(document.getElementById('sym-key').value);
    const iv = b64ToArray(document.getElementById('sym-iv').value);
    const aad = b64ToArray(document.getElementById('sym-aad').value);
    const plaintextString = document.getElementById('sym-enc-input').value;
    const plaintext = new TextEncoder().encode(plaintextString);
    try {
        const { ciphertext, tag } = await evp.symmetric.encrypt(alg, { key, iv, aad }, plaintext);
        document.getElementById('sym-enc-output').value = arrayToB64(ciphertext);
        document.getElementById('sym-enc-tag').value = arrayToB64(tag);
    } catch(err) {
        document.getElementById('sym-enc-output').value = 'Error: ' + err;
    }
}
async function symDecrypt() {
    const alg = document.getElementById('sym-alg').value;
    const key = b64ToArray(document.getElementById('sym-key').value);
    const iv = b64ToArray(document.getElementById('sym-iv').value);
    const aad = b64ToArray(document.getElementById('sym-aad').value);
    const tag = b64ToArray(document.getElementById('sym-dec-tag').value);
    const ciphertext = b64ToArray(document.getElementById('sym-dec-input').value);
    try {
        const plaintext = await evp.symmetric.decrypt(alg, { key, iv, aad, tag }, ciphertext);
        document.getElementById('sym-dec-output').value = String.fromCharCode(...plaintext);
    } catch(err) {
        document.getElementById('sym-dec-output').value = 'Error: ' + err;
}
}
async function pqcKeygen() {
    const alg = document.getElementById('pqc-alg').value;
    try {
        const { publicKey, privateKey } = await evp.pqc.keygen(alg);
        document.getElementById('pqc-keygen-pubkey').value = arrayToB64(publicKey);
        document.getElementById('pqc-keygen-privkey').value = arrayToB64(privateKey);
    } catch(err) {
        document.getElementById('pqc-keygen-pubkey').value = 'Error: ' + err;
    }
}
async function pqcEncap() {
    const alg = document.getElementById('pqc-alg').value;
    const pubkey = b64ToArray(document.getElementById('pqc-encaps-pubkey').value);
    try {
        const { ciphertext, sharedSecret } = await evp.pqc.encapsulate(alg, pubkey);
        document.getElementById('pqc-encaps-ciphertext').value = arrayToB64(ciphertext);
        document.getElementById('pqc-encaps-secret').value = arrayToB64(sharedSecret);
    } catch(err) {
        document.getElementById('pqc-encaps-ciphertext').value = 'Error: ' + err;
}
}
async function pqcDecap() {
    const alg = document.getElementById('pqc-alg').value;
    const privkey = b64ToArray(document.getElementById('pqc-decaps-privkey').value);
    const ciphertext = b64ToArray(document.getElementById('pqc-decaps-ciphertext').value);
    try {
        const sharedSecret = await evp.pqc.decapsulate(alg, privkey, ciphertext);
        document.getElementById('pqc-decaps-secret').value = arrayToB64(sharedSecret);
    } catch(err) {
        document.getElementById('pqc-decaps-secret').value = 'Error: ' + err;
    }
}

document.getElementById('generate-btn').onclick = generateBytes;
document.getElementById('gen-copy-btn').onclick = () => copyToClipboard('gen-output');

document.getElementById('sym-key-paste-btn').onclick = () => pasteFromClipboard('sym-key');
document.getElementById('sym-iv-paste-btn').onclick = () => pasteFromClipboard('sym-iv');
document.getElementById('sym-aad-paste-btn').onclick = () => pasteFromClipboard('sym-aad');

document.getElementById('sym-encrypt-btn').onclick = symEncrypt;
document.getElementById('sym-enc-copy-btn').onclick = () => copyToClipboard('sym-enc-output');
document.getElementById('sym-enc-tag-copy-btn').onclick = () => copyToClipboard('sym-enc-tag');

document.getElementById('sym-decrypt-btn').onclick = symDecrypt;
document.getElementById('sym-dec-paste-btn').onclick = () => pasteFromClipboard('sym-dec-input');
document.getElementById('sym-dec-tag-paste-btn').onclick = () => pasteFromClipboard('sym-dec-tag');

document.getElementById('pqc-keygen-btn').onclick = pqcKeygen;
document.getElementById('pqc-keygen-pubkey-copy-btn').onclick = () => copyToClipboard('pqc-keygen-pubkey');
document.getElementById('pqc-keygen-privkey-copy-btn').onclick = () => copyToClipboard('pqc-keygen-privkey');

document.getElementById('pqc-encaps-btn').onclick = pqcEncap;
document.getElementById('pqc-encaps-pubkey-paste-btn').onclick = () => pasteFromClipboard('pqc-encaps-pubkey');
document.getElementById('pqc-encaps-ciphertext-copy-btn').onclick = () => copyToClipboard('pqc-encaps-ciphertext');
document.getElementById('pqc-encaps-secret-copy-btn').onclick = () => copyToClipboard('pqc-encaps-secret');

document.getElementById('pqc-decaps-btn').onclick = pqcDecap;
document.getElementById('pqc-decaps-privkey-paste-btn').onclick = () => pasteFromClipboard('pqc-decaps-privkey');
document.getElementById('pqc-decaps-ciphertext-paste-btn').onclick = () => pasteFromClipboard('pqc-decaps-ciphertext');
document.getElementById('pqc-decaps-secret-copy-btn').onclick = () => copyToClipboard('pqc-decaps-secret');