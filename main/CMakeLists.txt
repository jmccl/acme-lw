file (GLOB_RECURSE source "*.cpp" "*.h")

add_executable(acme_lw_client ${source})
if (APPLE)
target_link_libraries(acme_lw_client PRIVATE acme_lw curl)
else()
target_link_libraries(acme_lw_client PRIVATE acme_lw curl stdc++fs)
endif()

install (TARGETS acme_lw_client DESTINATION bin)
