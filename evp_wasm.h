#pragma once
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <emscripten/val.h>

static std::vector<uint8_t> uint8ArrayToVector(const emscripten::val& arr) {
    if (arr.isArray() || arr.instanceof(emscripten::val::global("Uint8Array"))) {
        return emscripten::vecFromJSArray<uint8_t>(arr);
    }
    if (arr.instanceof(emscripten::val::global("ArrayBuffer"))) {
        emscripten::val uint8View = emscripten::val::global("Uint8Array").new_(arr);
        return emscripten::vecFromJSArray<uint8_t>(uint8View);
    }
    return std::vector<uint8_t>();
}

static emscripten::val vectorToUint8Array(const std::vector<uint8_t>& vec) {
    return emscripten::val::global("Uint8Array").new_(emscripten::val::array(vec));
}