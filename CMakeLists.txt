cmake_minimum_required(VERSION 3.20)
project(Share2Me VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------- Dependencies via FetchContent ----------
include(FetchContent)

# Crow (header-only HTTP framework)
FetchContent_Declare(
    crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG        v1.2.0
)

# nlohmann/json (header-only)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

FetchContent_MakeAvailable(crow nlohmann_json)

# ---------- Main executable ----------
add_executable(share2me src/main.cpp)

target_link_libraries(share2me
    PRIVATE
        Crow::Crow
        nlohmann_json::nlohmann_json
)

# Prefer a fully static binary (no shared-library dependencies at all).
# Requires: libstdc++-static, glibc-static (and libxcrypt-static on Fedora).
# Falls back to -static-libgcc -static-libstdc++ if full static isn't
# available, and to dynamic linking if even that fails.
if(UNIX AND NOT APPLE)
    include(CheckCXXSourceCompiles)

    set(CMAKE_REQUIRED_LINK_OPTIONS -static)
    check_cxx_source_compiles("int main(){return 0;}" HAS_FULL_STATIC)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)

    if(HAS_FULL_STATIC)
        target_link_options(share2me PRIVATE -static)
        message(STATUS "Fully static linking enabled")
    else()
        set(CMAKE_REQUIRED_LINK_OPTIONS -static-libgcc -static-libstdc++)
        check_cxx_source_compiles("int main(){return 0;}" HAS_STATIC_RUNTIME)
        unset(CMAKE_REQUIRED_LINK_OPTIONS)
        if(HAS_STATIC_RUNTIME)
            target_link_options(share2me PRIVATE -static-libgcc -static-libstdc++)
            message(STATUS "Static libgcc/libstdc++ linking enabled (glibc still dynamic)")
        else()
            message(STATUS "Static runtime libs not found – linking dynamically")
        endif()
    endif()
endif()

# ---------- Create data directory at build time ----------
add_custom_command(
    TARGET share2me POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            $<TARGET_FILE_DIR:share2me>/data
    COMMENT "Creating data/ directory next to binary"
)
