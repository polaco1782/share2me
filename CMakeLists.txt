cmake_minimum_required(VERSION 3.20)
project(Share2Me VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(ExternalProject)
include(FetchContent)
include(ProcessorCount)

ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 4)
endif()

# Ensure AR and RANLIB are resolved (needed when passing them to OpenSSL Configure)
if(NOT CMAKE_AR)
    find_program(CMAKE_AR ar REQUIRED)
endif()
if(NOT CMAKE_RANLIB)
    find_program(CMAKE_RANLIB ranlib)
    if(NOT CMAKE_RANLIB)
        set(CMAKE_RANLIB true)   # no-op fallback
    endif()
endif()

# ---------------------------------------------------------------------------
# All vendored dependencies install under a single prefix.
# ---------------------------------------------------------------------------
set(DEPS_PREFIX "${CMAKE_BINARY_DIR}/deps-prefix")

file(MAKE_DIRECTORY "${DEPS_PREFIX}/include")
file(MAKE_DIRECTORY "${DEPS_PREFIX}/lib")

# ===========================================================================
# OpenSSL 3.4.1  -  static, minimal feature set
# ===========================================================================

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(_OSSL_TARGET "linux-x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(_OSSL_TARGET "linux-aarch64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armv7|armhf")
    set(_OSSL_TARGET "linux-armv4")
else()
    set(_OSSL_TARGET "linux-generic64")
endif()

ExternalProject_Add(openssl_ext
    URL         https://github.com/openssl/openssl/releases/download/openssl-3.4.1/openssl-3.4.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP ON

    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env
            CC=${CMAKE_C_COMPILER}
            AR=${CMAKE_AR}
            RANLIB=${CMAKE_RANLIB}
        <SOURCE_DIR>/Configure
            no-shared
            no-tests
            no-apps
            no-docs
            no-legacy
            no-comp
            --prefix=${DEPS_PREFIX}
            --libdir=lib
            --openssldir=${DEPS_PREFIX}/ssl
            ${_OSSL_TARGET}

    BUILD_COMMAND   make -j${NPROC}
    INSTALL_COMMAND sh -c "make install_sw && rm -rf ${DEPS_PREFIX}/lib/cmake"
    BUILD_IN_SOURCE TRUE
    LOG_DOWNLOAD    ON
    LOG_CONFIGURE   ON
    LOG_BUILD       ON
    LOG_INSTALL     ON
)

add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION             "${DEPS_PREFIX}/lib/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${DEPS_PREFIX}/include"
    INTERFACE_LINK_LIBRARIES      "dl;pthread"
)
add_dependencies(OpenSSL::Crypto openssl_ext)

add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION             "${DEPS_PREFIX}/lib/libssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${DEPS_PREFIX}/include"
    INTERFACE_LINK_LIBRARIES      "OpenSSL::Crypto"
)
add_dependencies(OpenSSL::SSL openssl_ext)

# ===========================================================================
# cpp-httplib (header-only) + nlohmann/json v3.11.3 (header-only)
# ===========================================================================

# Disable optional deps that aren't available as static libraries
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE   OFF CACHE BOOL "" FORCE)
# We manage OpenSSL ourselves; tell httplib not to search for it
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        v0.18.3
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

FetchContent_MakeAvailable(cpp_httplib nlohmann_json)

# ===========================================================================
# Main executable
# ===========================================================================

add_executable(share2me
    src/main.cpp
    src/acme_client.cpp
    src/cert_manager.cpp
    src/config.cpp
    src/hash.cpp
    src/housekeeper.cpp
    src/mime.cpp
    src/page.cpp
    src/routes.cpp
    src/sandbox.cpp
    src/ssl_manager.cpp
    src/store.cpp
    src/tls_util.cpp
)

target_include_directories(share2me
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(share2me
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
)

target_link_libraries(share2me
    PRIVATE
        httplib::httplib
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
)

add_dependencies(share2me openssl_ext)

# ===========================================================================
# Static linking strategy
# ===========================================================================
if(UNIX AND NOT APPLE)
    include(CheckCXXSourceCompiles)

    set(CMAKE_REQUIRED_LINK_OPTIONS -static)
    check_cxx_source_compiles("int main(){return 0;}" HAS_FULL_STATIC)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)

    if(HAS_FULL_STATIC)
        target_link_options(share2me PRIVATE -static)
        message(STATUS "Fully static linking enabled (zero shared-library dependencies)")
    else()
        set(CMAKE_REQUIRED_LINK_OPTIONS -static-libgcc -static-libstdc++)
        check_cxx_source_compiles("int main(){return 0;}" HAS_STATIC_RUNTIME)
        unset(CMAKE_REQUIRED_LINK_OPTIONS)

        if(HAS_STATIC_RUNTIME)
            target_link_options(share2me PRIVATE -static-libgcc -static-libstdc++)
            message(STATUS "Static libgcc/libstdc++ enabled  (glibc remains dynamic)")
        else()
            message(STATUS "No static runtime available - linking fully dynamically")
        endif()
    endif()
endif()

# ===========================================================================
# Release hardening
# ===========================================================================
if(UNIX AND NOT APPLE)
    include(CheckLinkerFlag)
    check_linker_flag(CXX -pie                  LINKER_HAS_PIE)
    check_linker_flag(CXX "-Wl,-z,relro"        LINKER_HAS_RELRO)
    check_linker_flag(CXX "-Wl,-z,now"          LINKER_HAS_BIND_NOW)

    target_compile_options(share2me PRIVATE
        $<$<CONFIG:Release>:-fPIE>
        $<$<CONFIG:Release>:-U_FORTIFY_SOURCE>
        $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>
    )

    if(LINKER_HAS_PIE)
        target_link_options(share2me PRIVATE $<$<CONFIG:Release>:-pie>)
    endif()
    if(LINKER_HAS_RELRO)
        target_link_options(share2me PRIVATE $<$<CONFIG:Release>:-Wl,-z,relro>)
    endif()
    if(LINKER_HAS_BIND_NOW)
        target_link_options(share2me PRIVATE $<$<CONFIG:Release>:-Wl,-z,now>)
    endif()

    message(STATUS "Release hardening: PIE=${LINKER_HAS_PIE}  RELRO=${LINKER_HAS_RELRO}  BIND_NOW=${LINKER_HAS_BIND_NOW}  FORTIFY_SOURCE=2")
endif()

# ===========================================================================
# Post-build: create data/ directory next to the binary
# ===========================================================================
add_custom_command(
    TARGET share2me POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            $<TARGET_FILE_DIR:share2me>/data
    COMMENT "Creating data/ directory next to the binary"
)
