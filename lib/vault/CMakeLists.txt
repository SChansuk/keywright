find_package(unofficial-sodium CONFIG REQUIRED)
find_package(utf8proc CONFIG REQUIRED)

add_library(vault STATIC  "internal.h" "names.cpp" "crypto.cpp" "payload.cpp" "vault.cpp")
add_library(keywright::vault ALIAS vault)

target_include_directories(vault PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(vault
  PUBLIC keywright::secrets
  PRIVATE unofficial-sodium::sodium utf8proc::utf8proc)
set_target_properties(vault PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
