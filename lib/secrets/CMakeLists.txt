add_library(secrets STATIC "swipe.cpp" "secret_buffer.cpp")
add_library(keywright::secrets ALIAS secrets)

target_include_directories(secrets PUBLIC ${PROJECT_SOURCE_DIR}/include)
set_target_properties(secrets PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
