file (GLOB_RECURSE source "*.cpp" "*.h")

include(CheckIncludeFileCXX)
check_include_file_cxx(experimental/filesystem EXPERIMENTAL_FILESYSTEM)
if (EXPERIMENTAL_FILESYSTEM)
add_definitions(-DEXPERIMENTAL_FILESYSTEM)
endif ()

add_executable(acme_lw_client ${source})

include(CheckLibraryExists)
check_library_exists(stdc++fs chdir "" EXTERNAL_FS_LIBRARY)

if (EXTERNAL_FS_LIBRARY)
target_link_libraries(acme_lw_client PRIVATE acme_lw curl stdc++fs)
else()
target_link_libraries(acme_lw_client PRIVATE acme_lw curl)
endif()

install (TARGETS acme_lw_client DESTINATION bin)
