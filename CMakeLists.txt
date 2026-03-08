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
# All vendored dependencies install under a single prefix.  OpenSSL is built
# first; curl is pointed at that same prefix so its CMake find_package(OpenSSL)
# picks up our static libs instead of any system copy.
# ---------------------------------------------------------------------------
set(DEPS_PREFIX "${CMAKE_BINARY_DIR}/deps-prefix")

# Create the include dir now - CMake validates INTERFACE_INCLUDE_DIRECTORIES
# on IMPORTED targets at configure time, before ExternalProject has run.
file(MAKE_DIRECTORY "${DEPS_PREFIX}/include")
file(MAKE_DIRECTORY "${DEPS_PREFIX}/lib")

# ===========================================================================
# OpenSSL 3.4.1  -  static, minimal feature set
#
# Built with OpenSSL's own perl Configure script.
# URL_HASH lines are commented out; uncomment and fill in the SHA-256 of the
# tarball for reproducible / auditable builds:
#   sha256sum openssl-3.4.1.tar.gz
# ===========================================================================

# Map CMake's CPU identifier to an OpenSSL Configure target triple.
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
    # URL_HASH  SHA256=<sha256-of-tarball>
    DOWNLOAD_EXTRACT_TIMESTAMP ON

    # Pass the same compiler/archiver the parent project uses.
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env
            CC=${CMAKE_C_COMPILER}
            AR=${CMAKE_AR}
            RANLIB=${CMAKE_RANLIB}
        <SOURCE_DIR>/Configure
            no-shared       # static libs only - no libssl.so / libcrypto.so
            no-tests        # skip the test suite
            no-apps         # skip the openssl(1) CLI binary
            no-docs         # skip man-page generation
            no-legacy       # drop obsolete ciphers (IDEA, RC4, …)
            no-comp         # no zlib/bzip2 compression support
            --prefix=${DEPS_PREFIX}
            --libdir=lib    # always lib/, not lib64/, for a predictable path
            --openssldir=${DEPS_PREFIX}/ssl
            ${_OSSL_TARGET}

    BUILD_COMMAND   make -j${NPROC}
    # install_sw installs headers + libs but skips man pages.
    # We then remove OpenSSL's own CMake package-config files so that curl's
    # find_package(OpenSSL) falls back to CMake's FindOpenSSL.cmake module.
    # OpenSSLConfig.cmake (installed by OpenSSL 3.x) lists ZLIB::ZLIB in
    # OpenSSL::SSL's link interface even when built with no-comp; that target
    # is unavailable in curl's fresh sub-build and causes a configure error.
    INSTALL_COMMAND sh -c "make install_sw && rm -rf ${DEPS_PREFIX}/lib/cmake"
    BUILD_IN_SOURCE TRUE
    LOG_DOWNLOAD    ON
    LOG_CONFIGURE   ON
    LOG_BUILD       ON
    LOG_INSTALL     ON
)

# IMPORTED targets - paths are known once install_sw has run at build time.
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
# curl 8.12.1  -  static, HTTPS-only, backed by the OpenSSL we just built
#
# URL_HASH line is commented out; fill in for reproducible builds:
#   sha256sum curl-8.12.1.tar.gz
# ===========================================================================

ExternalProject_Add(curl_ext
    DEPENDS openssl_ext

    URL         https://curl.se/download/curl-8.12.1.tar.gz
    # URL_HASH  SHA256=<sha256-of-tarball>
    DOWNLOAD_EXTRACT_TIMESTAMP ON

    # Override the configure step so we can prepend our deps-prefix to
    # PKG_CONFIG_PATH before cmake runs.  This is critical: CMake's
    # FindOpenSSL.cmake calls pkg_check_modules with --static, which reads
    # Libs.private from the first openssl.pc it finds.  The *system*
    # libcrypto.pc has "-lz" there (even on a no-zlib OpenSSL build on Fedora),
    # causing FindOpenSSL to inject ZLIB::ZLIB into OpenSSL's link interface -
    # a target that doesn't exist in curl's fresh sub-build.  Our custom
    # libcrypto.pc (built with no-comp) has no "-lz", so routing pkg-config
    # to our prefix first avoids that spurious ZLIB dependency.
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env
            PKG_CONFIG_PATH=${DEPS_PREFIX}/lib/pkgconfig
        ${CMAKE_COMMAND}
            -G "${CMAKE_GENERATOR}"
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_INSTALL_PREFIX=${DEPS_PREFIX}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DCMAKE_BUILD_TYPE=Release
            # Static only - no libcurl.so
            -DBUILD_SHARED_LIBS=OFF
            # Skip curl CLI and tests
            -DBUILD_CURL_EXE=OFF
            -DBUILD_TESTING=OFF
            # TLS backend: our static OpenSSL
            -DCURL_USE_OPENSSL=ON
            -DOPENSSL_ROOT_DIR=${DEPS_PREFIX}
            -DOPENSSL_INCLUDE_DIR=${DEPS_PREFIX}/include
            -DOPENSSL_SSL_LIBRARY=${DEPS_PREFIX}/lib/libssl.a
            -DOPENSSL_CRYPTO_LIBRARY=${DEPS_PREFIX}/lib/libcrypto.a
            -DOPENSSL_USE_STATIC_LIBS=ON
            # Disable optional dependencies we don't need
            -DUSE_LIBIDN2=OFF
            -DUSE_NGHTTP2=OFF
            -DUSE_NGTCP2=OFF
            -DCURL_USE_LIBPSL=OFF
            -DCURL_USE_LIBSSH2=OFF
            -DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=ON
            # Disable content-encoding libs (brotli, zstd) - share2me doesn't
            # need response decompression and these aren't available statically.
            -DCMAKE_DISABLE_FIND_PACKAGE_Brotli=ON
            -DCMAKE_DISABLE_FIND_PACKAGE_Zstd=ON
            -DCURL_BROTLI=OFF
            -DCURL_ZSTD=OFF
            # Disable every protocol except HTTP / HTTPS
            -DCURL_DISABLE_LDAP=ON
            -DCURL_DISABLE_LDAPS=ON
            -DCURL_DISABLE_FTP=ON
            -DCURL_DISABLE_IMAP=ON
            -DCURL_DISABLE_POP3=ON
            -DCURL_DISABLE_SMTP=ON
            -DCURL_DISABLE_TELNET=ON
            -DCURL_DISABLE_TFTP=ON
            -DCURL_DISABLE_DICT=ON
            -DCURL_DISABLE_GOPHER=ON
            -DCURL_DISABLE_MQTT=ON
            -DCURL_DISABLE_RTSP=ON
            -DCURL_DISABLE_SMB=ON
            -DCURL_DISABLE_WEBSOCKETS=ON
            -S <SOURCE_DIR>
            -B <BINARY_DIR>

    BUILD_COMMAND   ${CMAKE_COMMAND} --build   <BINARY_DIR> --parallel ${NPROC}
    INSTALL_COMMAND ${CMAKE_COMMAND} --install <BINARY_DIR>

    LOG_DOWNLOAD    ON
    LOG_CONFIGURE   ON
    LOG_BUILD       ON
    LOG_INSTALL     ON
)

add_library(CURL::libcurl STATIC IMPORTED GLOBAL)
set_target_properties(CURL::libcurl PROPERTIES
    IMPORTED_LOCATION             "${DEPS_PREFIX}/lib/libcurl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${DEPS_PREFIX}/include"
    # Transitive deps of a statically linked libcurl
    INTERFACE_LINK_LIBRARIES      "OpenSSL::SSL;OpenSSL::Crypto;dl;pthread;resolv"
)
add_dependencies(CURL::libcurl curl_ext)

# ===========================================================================
# Crow v1.2.0 (header-only) + nlohmann/json v3.11.3 (header-only)
#
# IMPORTANT: do NOT set CROW_FEATURES=ssl here.
# Crow's CMakeLists calls find_package(OpenSSL REQUIRED) at *configure* time
# when "ssl" is in CROW_FEATURES.  Our OpenSSL ExternalProject only runs at
# *build* time, so the headers / libs don't exist yet during
# FetchContent_MakeAvailable.  We apply CROW_ENABLE_SSL and link OpenSSL
# directly to our target below - achieving the same effect without triggering
# Crow's configure-time OpenSSL lookup.
# ===========================================================================

FetchContent_Declare(
    crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG        v1.2.0
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

FetchContent_MakeAvailable(crow nlohmann_json)

# ===========================================================================
# Main executable
# ===========================================================================

add_executable(share2me src/main.cpp)

# CROW_ENABLE_SSL is the definition Crow normally injects when CROW_FEATURES=ssl.
# Setting it here bypasses Crow's configure-time OpenSSL search while still
# activating all TLS code paths in the Crow and Asio headers.
target_compile_definitions(share2me
    PRIVATE
        CROW_ENABLE_SSL     # activate Crow/Asio TLS code paths
)

target_link_libraries(share2me
    PRIVATE
        Crow::Crow
        nlohmann_json::nlohmann_json
        OpenSSL::SSL        # libssl.a  (depends on OpenSSL::Crypto)
        OpenSSL::Crypto     # libcrypto.a
        CURL::libcurl       # libcurl.a (HTTPS only)
)

# Belt-and-suspenders: the IMPORTED targets already carry add_dependencies(),
# but being explicit here makes "cmake --build . --target share2me" reliable
# even if the dependency graph is evaluated lazily.
add_dependencies(share2me openssl_ext curl_ext)

# ===========================================================================
# Static linking strategy
#
# Priority order (best to worst):
#   1. Fully static (-static): requires glibc-static (libc.a, libm.a, …).
#      Produces a binary with zero shared-library dependencies.
#   2. Static C++ / GCC runtime only (-static-libgcc -static-libstdc++):
#      glibc stays dynamic but libstdc++.a and libgcc_eh.a are embedded.
#   3. Fully dynamic: no extra flags.
#
# The checks use try_compile so they respect cross-compilation toolchains.
# OpenSSL and curl are already compiled as .a archives, so the only remaining
# dynamic dependency at this point is glibc.
# ===========================================================================
if(UNIX AND NOT APPLE)
    include(CheckCXXSourceCompiles)

    # --- attempt 1: fully static -------------------------------------------
    set(CMAKE_REQUIRED_LINK_OPTIONS -static)
    check_cxx_source_compiles("int main(){return 0;}" HAS_FULL_STATIC)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)

    if(HAS_FULL_STATIC)
        target_link_options(share2me PRIVATE -static)
        message(STATUS "Fully static linking enabled (zero shared-library dependencies)")
    else()
        # --- attempt 2: static C++ / GCC runtime only ----------------------
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
# Release hardening: PIE, full RELRO, FORTIFY_SOURCE=2
#
# PIE:            -fPIE (compile) + -pie (link).  When -static is already
#                 active the linker produces a static-PIE (glibc ≥ 2.27).
# Full RELRO:     -Wl,-z,relro,-z,now  marks the GOT/PLT read-only after
#                 start-up and binds all symbols eagerly (no lazy binding).
#                 Harmless for static binaries - the kernel honours the
#                 PT_GNU_RELRO segment even without ld.so.
# FORTIFY_SOURCE: replaces unsafe libc calls with bounds-checked variants.
#                 Level 2 requires at least -O1; Release defaults to -O3.
#                 -U first avoids "redefinition" warnings on distros that
#                 already set _FORTIFY_SOURCE in their default flags.
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
