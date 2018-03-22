file (GLOB_RECURSE source "*.cpp" "*.h")

add_executable(acme_lw_client ${source})

target_link_libraries(acme_lw_client PRIVATE acme_lw curl stdc++fs)
