find_package(Catch2 3 CONFIG REQUIRED)
include(Catch)

add_executable(secrets_tests "secrets_tests.cpp")
target_link_libraries(secrets_tests PRIVATE keywright::secrets Catch2::Catch2WithMain)
set_property(TARGET secrets_tests PROPERTY CXX_STANDARD 20)

catch_discover_tests(secrets_tests)

add_executable(vault_tests "vault_tests.cpp")
target_link_libraries(vault_tests PRIVATE keywright::vault Catch2::Catch2WithMain)
set_property(TARGET vault_tests PROPERTY CXX_STANDARD 20)

catch_discover_tests(vault_tests)

add_executable(platform_tests "platform_tests.cpp")
target_link_libraries(platform_tests PRIVATE keywright::platform Catch2::Catch2WithMain)
set_property(TARGET platform_tests PROPERTY CXX_STANDARD 20)

catch_discover_tests(platform_tests)

add_executable(config_tests config_tests.cpp)
target_link_libraries(config_tests PRIVATE keywright::config keywright::platform Catch2::Catch2WithMain)
target_compile_definitions(config_tests PRIVATE KWR_PASSGEN_TOML="${CMAKE_CURRENT_SOURCE_DIR}/passgen.toml")
set_property(TARGET config_tests PROPERTY CXX_STANDARD 20)

catch_discover_tests(config_tests)
