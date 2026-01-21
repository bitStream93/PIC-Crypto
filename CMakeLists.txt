cmake_minimum_required(VERSION 3.20)


project(crypto LANGUAGES C CXX ASM_NASM)
set(CMAKE_CXX_STANDARD 23)
set(SERVER_NAME server)
set(CLIENT_NAME client)


if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif ()


set(CMAKE_C_STANDARD_LIBRARIES "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")

set(CMAKE_EXE_LINKER_FLAGS "")
set(CMAKE_SHARED_LINKER_FLAGS "")
set(CMAKE_MODULE_LINKER_FLAGS "")


set(BIN_DIR ${CMAKE_BINARY_DIR}/bin)
file(MAKE_DIRECTORY ${BIN_DIR})


set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)

set(CMAKE_C_COMPILER_TARGET x86_64-w64-mingw32)
set(CMAKE_CXX_COMPILER_TARGET x86_64-w64-mingw32)


set(CMAKE_LINKER ld)
set(CMAKE_C_FLAGS_INIT "")
set(CMAKE_CXX_FLAGS_INIT "")


set(CMAKE_C_LINK_EXECUTABLE
        "<CMAKE_C_COMPILER> <OBJECTS> -o <TARGET> <LINK_FLAGS>"
)
set(CMAKE_CXX_LINK_EXECUTABLE
        "<CMAKE_CXX_COMPILER> <OBJECTS> -o <TARGET> <LINK_FLAGS>"
)


enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)


if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(OBJCOPY x86_64-w64-mingw32-objcopy)
else ()
    set(OBJCOPY objcopy)
endif ()


set(CRYPTO_CFLAGS
        -Os
        -nostdlib
        -fno-builtin
        -fno-builtin-memset
        -fno-builtin-memcpy
        -fno-builtin-strcpy
        -fno-lto
        -fno-asynchronous-unwind-tables
        -fno-ident
        -fpack-struct=8
        -falign-functions=1
        -s
        -w
        -msse2
        -msse4.1
        -march=native
        -fno-rtti
        -fno-threadsafe-statics
        -fno-stack-check
        -ffunction-sections
        -falign-jumps=1
        -falign-labels=1
        -masm=intel
        -fno-exceptions
        -fms-extensions
        -fPIC
        -I${CMAKE_SOURCE_DIR}/include/misc
        -I${CMAKE_SOURCE_DIR}/include/crypto
        -DDEBUG
        -mno-stack-arg-probe
        -fno-stack-protector

)

set(CRYPTO_LDFLAGS
        -nostdlib
        -Wl,-s,--no-seh,--enable-stdcall-fixup
        -Wl,-T,${CMAKE_SOURCE_DIR}/scripts/linker.ld
        -ldnsapi
)


file(GLOB CRYPTO_SRC src/crypto/*.cc)
file(GLOB CRYPTO_ASM src/asm/*.x64.asm)
file(GLOB MISC_SRC src/misc/*.cc)
file(GLOB SERVER_SRC src/server.cc)
file(GLOB CLIENT_SRC src/client.cc)


add_executable(${SERVER_NAME}.x64.exe
        ${SERVER_SRC}
        ${MISC_SRC}
        ${CRYPTO_SRC}
        ${CRYPTO_ASM}
)

add_executable(${CLIENT_NAME}.x64.exe
        ${CLIENT_SRC}
        ${MISC_SRC}
        ${CRYPTO_SRC}
        ${CRYPTO_ASM}
)

set_target_properties(${SERVER_NAME}.x64.exe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
        OUTPUT_NAME "${SERVER_NAME}.x64"
)
set_target_properties(${CLIENT_NAME}.x64.exe PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
        OUTPUT_NAME "${CLIENT_NAME}.x64"
)
target_compile_options(${SERVER_NAME}.x64.exe PRIVATE
        $<$<COMPILE_LANGUAGE:C>:${CRYPTO_CFLAGS}>
        $<$<COMPILE_LANGUAGE:CXX>:${CRYPTO_CFLAGS}>
        $<$<COMPILE_LANGUAGE:ASM_NASM>:-f win64>
)
target_compile_options(${CLIENT_NAME}.x64.exe PRIVATE
        $<$<COMPILE_LANGUAGE:C>:${CRYPTO_CFLAGS}>
        $<$<COMPILE_LANGUAGE:CXX>:${CRYPTO_CFLAGS}>
        $<$<COMPILE_LANGUAGE:ASM_NASM>:-f win64>

)

target_link_options(${SERVER_NAME}.x64.exe PRIVATE
        ${CRYPTO_LDFLAGS}
)
target_link_options(${CLIENT_NAME}.x64.exe PRIVATE
        ${CRYPTO_LDFLAGS}
)


set_property(TARGET ${SERVER_NAME}.x64.exe PROPERTY LINK_LIBRARIES "")
set_property(TARGET ${CLIENT_NAME}.x64.exe PROPERTY LINK_LIBRARIES "")


add_custom_command(
        TARGET ${SERVER_NAME}.x64.exe
        POST_BUILD
        COMMAND ${OBJCOPY}
        --dump-section .text=${BIN_DIR}/${SERVER_NAME}.x64.bin
        ${BIN_DIR}/${SERVER_NAME}.x64.exe
)
add_custom_command(
        TARGET ${CLIENT_NAME}.x64.exe
        POST_BUILD
        COMMAND ${OBJCOPY}
        --dump-section .text=${BIN_DIR}/${CLIENT_NAME}.x64.bin
        ${BIN_DIR}/${CLIENT_NAME}.x64.exe
)
include(ExternalProject)

ExternalProject_Add(loader_project
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/loader"

        CONFIGURE_COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}"
        -DCMAKE_CXX_COMPILER=g++
        -DCMAKE_EXE_LINKER_FLAGS=-static
        -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=${CMAKE_BINARY_DIR}/bin
        "${CMAKE_CURRENT_SOURCE_DIR}/loader"

        BUILD_COMMAND "${CMAKE_COMMAND}" --build .
        INSTALL_COMMAND ""
)

add_dependencies(${SERVER_NAME}.x64.exe loader_project)