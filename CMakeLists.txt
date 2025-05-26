cmake_minimum_required(VERSION 3.2...3.31)
   
if (WIN32)
   set(CMAKE_TOOLCHAIN_FILE $ENV{VS_ROOT}/VC/vcpkg/scripts/buildsystems/vcpkg.cmake)
endif()

project (acme_lw_client)

include(CheckIncludeFileCXX)
check_include_file_cxx(filesystem STD_FILESYSTEM)
if (STD_FILESYSTEM)
   set (CMAKE_CXX_STANDARD 17)
else()
   set (CMAKE_CXX_STANDARD 14)
endif()

OPTION(STAGING "Run against the Let's Encrypt staging environment" OFF)
if (STAGING)
   message(FATAL_ERROR "Use of the staging environment is no longer controlled at compile time. See 'acme-lw.h' for runtime control.")
endif ()

OPTION(ASAN "Build with asan" OFF)
if (ASAN)
   set(CMAKE_BUILD_TYPE "Debug")
   set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,leak -fno-omit-frame-pointer")
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,leak -fno-omit-frame-pointer")
endif ()

# -Wno-unqualified-std-cast-call is a new clang (15+) warning, which
# for the moment I'm regarding as misguided, for the reason given here
# https://www.mail-archive.com/cfe-commits@lists.llvm.org/msg266260.html
# This requires -Wno-unknown-warning-option to deal with older clang versions
if (NOT WIN32)
   add_compile_options (-Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Werror -Wno-unqualified-std-cast-call -Wno-unknown-warning-option)
else()
   add_compile_options (/W4 /WX)
endif()

add_subdirectory (lib)
add_subdirectory (main)
