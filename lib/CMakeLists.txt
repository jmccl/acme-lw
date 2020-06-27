file (GLOB_RECURSE source "*.cpp" "*.h" "../internal/*.h" "../internal/*.cpp")

add_library(acme_lw ${source})

install (TARGETS acme_lw DESTINATION lib)
install (FILES acme-exception.h acme-lw.h DESTINATION include)

target_include_directories(acme_lw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../internal ${OPENSSL_INCLUDE_DIR})

target_link_libraries(acme_lw PRIVATE crypto)
