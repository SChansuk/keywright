add_library(platform STATIC "paths.cpp" "files.cpp" "console.cpp" "clipboard.cpp" "internal.h")
add_library(keywright::platform ALIAS platform)

target_include_directories(platform PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(platform
  PUBLIC keywright::secrets
  PRIVATE $<$<PLATFORM_ID:Windows>:shell32 ole32 user32 advapi32>)
set_target_properties(platform PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
