file (GLOB_RECURSE source "*.cpp" "*.h")

if (STD_FILESYSTEM)
add_definitions(-DSTD_FILESYSTEM)
endif ()

add_executable(acme_lw_client ${source})

include(CheckLibraryExists)
check_library_exists(stdc++fs chdir "" EXTERNAL_FS_LIBRARY)

if (EXTERNAL_FS_LIBRARY)
target_link_libraries(acme_lw_client PRIVATE acme_lw stdc++fs)
else()
target_link_libraries(acme_lw_client PRIVATE acme_lw)
endif()

install (TARGETS acme_lw_client DESTINATION bin)
