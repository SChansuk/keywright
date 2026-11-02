find_package(tomlplusplus CONFIG REQUIRED)

add_library(config STATIC "config.cpp")
add_library(keywright::config ALIAS config)

target_include_directories(config PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(config PRIVATE tomlplusplus::tomlplusplus)
set_target_properties(config PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
