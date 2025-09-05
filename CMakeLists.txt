cmake_minimum_required(VERSION 3.16)

enable_testing()

project(openssl_wasm_project)

set(CMAKE_CXX_STANDARD_REQUIRED ON) 
set(CMAKE_CXX_STANDARD          ${CONAN_CMAKE_CXX_STANDARD}) 
set(CMAKE_CXX_EXTENSIONS        ${CONAN_CMAKE_CXX_EXTENSIONS})

set(WASM_TARGET openssl_wasm)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

find_package(OpenSSL MODULE REQUIRED)


file(GLOB WASM_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(${WASM_TARGET} ${WASM_SOURCES})
target_include_directories(${WASM_TARGET} PRIVATE
    ${OpenSSL_INCLUDE_DIRS})
target_link_libraries(${WASM_TARGET} PRIVATE openssl::openssl)

set(WASM_LINKER_OPTS
    -sFETCH
    -03
    -Wno-pthreads-mem-growth
    -sMODULARIZE=1
    -sEXPORT_ES6=1
    -sEXPORT_NAME=${WASM_TARGET}
    -sEXPORTED_FUNCTIONS=[___get_exception_message]
    -sEXPORTED_RUNTIME_METHODS=[allocateUTF8,UTF8ToString,wasmMemory,getExceptionMessage,stringToUTF8,lengthBytesUTF8]
    -sSTACK_OVERFLOW_CHECK=1
    -sALLOW_MEMORY_GROWTH=1
    -sDEMANGLE_SUPPORT=1
    -sASSERTIONS
    -lembind
    -sSAFE_HEAP=1
    -sASSERTIONS=2
    -fprofiling-funcs
    -sNO_EXIT_RUNTIME
    -sNO_DISABLE_EXCEPTION_CATCHING
    -v
)

target_link_options(${WASM_TARGET} PRIVATE ${WASM_LINKER_OPTS})

add_custom_command(
    TARGET  ${WASM_TARGET}  POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${WASM_TARGET}.js
            ${CMAKE_CURRENT_SOURCE_DIR}/test/public/${WASM_TARGET}.js)
add_custom_command(
    TARGET  ${WASM_TARGET}  POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${WASM_TARGET}.wasm
            ${CMAKE_CURRENT_SOURCE_DIR}/test/public/${WASM_TARGET}.wasm)

install(FILES
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${WASM_TARGET}.js
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${WASM_TARGET}.wasm
    DESTINATION .
)
