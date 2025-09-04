/*
 * ATTENTION: The "eval" devtool has been used (maybe by default in mode: "development").
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./openssl_wasm.ts":
/*!*************************!*\
  !*** ./openssl_wasm.ts ***!
  \*************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

eval("{__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   OpensslEVP: () => (/* binding */ OpensslEVP)\n/* harmony export */ });\nvar __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {\n    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }\n    return new (P || (P = Promise))(function (resolve, reject) {\n        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }\n        function rejected(value) { try { step(generator[\"throw\"](value)); } catch (e) { reject(e); } }\n        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }\n        step((generator = generator.apply(thisArg, _arguments || [])).next());\n    });\n};\nclass OpensslEVP {\n    constructor() { }\n    load(wasmPath) {\n        return __awaiter(this, void 0, void 0, function* () {\n            // Emscripten-generated WASM modules typically export a factory function\n            // that returns a promise resolving to the module instance\n            this.bindings = yield window[wasmPath]();\n        });\n    }\n    generateAsymmetricKeyPair(algorithm) {\n        return this.bindings.generateAsymmetricKeyPair(algorithm);\n    }\n    generateSymmetricKey(algorithm, keyLength) {\n        return this.bindings.generateSymmetricKey(algorithm, keyLength);\n    }\n    encapsulate(algorithm, publicKey) {\n        return this.bindings.encapsulate(algorithm, publicKey);\n    }\n    decapsulate(algorithm, privateKey, ciphertext) {\n        return this.bindings.decapsulate(algorithm, privateKey, ciphertext);\n    }\n    encrypt(algorithm, key, iv, plaintext) {\n        return this.bindings.encrypt(algorithm, key, iv, plaintext);\n    }\n    decrypt(algorithm, key, iv, ciphertext) {\n        return this.bindings.decrypt(algorithm, key, iv, ciphertext);\n    }\n    getSupportedAlgorithms() {\n        return this.bindings.getSupportedAlgorithms();\n    }\n}\n\n\n//# sourceURL=webpack://OpensslEVP/./openssl_wasm.ts?\n}");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The require scope
/******/ 	var __webpack_require__ = {};
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module can't be inlined because the eval devtool is used.
/******/ 	var __webpack_exports__ = {};
/******/ 	__webpack_modules__["./openssl_wasm.ts"](0, __webpack_exports__, __webpack_require__);
/******/ 	window.OpensslEVP = __webpack_exports__;
/******/ 	
/******/ })()
;