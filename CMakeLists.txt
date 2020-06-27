cmake_minimum_required(VERSION 3.2)
project (acme_lw_client)

find_package (CURL REQUIRED)
find_package (OpenSSL REQUIRED)

set (acme_lw_client_VERSION_MAJOR 0)
set (acme_lw_client_VERSION_MINOR 3)
set (acme_lw_client_VERSION_PATCH 0)
set (CMAKE_CXX_STANDARD 17)

OPTION(STAGING "Run against the Let's Encrypt staging environment" OFF)
if (STAGING)
   add_definitions (-DSTAGING)
endif ()

add_compile_options (-Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Werror)

add_subdirectory (lib)
add_subdirectory (main)
